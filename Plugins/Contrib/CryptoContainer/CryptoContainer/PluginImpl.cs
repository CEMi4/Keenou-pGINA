/*
 * Keenou
 * Copyright (C) 2015  Charles Munson
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

using System;
using pGina.Shared.Types;
using Microsoft.Win32;
using System.Security.Principal;
using System.Diagnostics;
using System.IO;
using log4net;

namespace pGina.Plugin.CryptoContainer
{
    public class PluginImpl : pGina.Shared.Interfaces.IPluginAuthenticationGateway
    {
        private static readonly Guid m_uuid = new Guid("14EFCEF3-4D67-44C6-9F28-BB80F1A33827");
        private ILog m_logger;

        public PluginImpl()
        {
            m_logger = LogManager.GetLogger("pGina.Plugin.CryptoContainer");
        }

        public string Name
        {
            get { return "CryptoContainer"; }
        }

        public string Description
        {
            get { return "Authenticates users with an encrypted home folder."; }
        }

        public Guid Uuid
        {
            get { return m_uuid; }
        }

        public string Version
        {
            get
            {
                return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
            }
        }

        public void Starting() { }

        public void Stopping() { }


        public BooleanResult AuthenticatedUserGateway(SessionProperties properties)
        {

            // Get SID of user //
            UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();
            NTAccount acct = new NTAccount(userInfo.Username);
            SecurityIdentifier s = (SecurityIdentifier)acct.Translate(typeof(SecurityIdentifier));
            String sidString = s.ToString();
            m_logger.InfoFormat("SID for user: {0}", sidString);
            // * //



            // Obtain system-defined home folder for user //
            string homeFolder = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sidString, "ProfileImagePath", null);
            if (string.IsNullOrEmpty(homeFolder))
            {
                return new BooleanResult() { Success = false, Message = "Cannot find user's ProfileImagePath in registry." };
            }
            m_logger.InfoFormat("Current home folder: {0}", homeFolder);
            // * //



            // Figure out the hash used for crypto container //
            string hashChosen = (string)Registry.GetValue(Keenou.Config.LOCAL_MACHINE_REG_ROOT + sidString, "hash", "whirlpool");
            if (string.IsNullOrEmpty(hashChosen))
            {
                return new BooleanResult() { Success = false, Message = "Cannot find user's hash algorithm in registry." };
            }
            m_logger.InfoFormat("Hash algorithm: {0}", hashChosen);
            // * //



            // Figure out where the home folder's encrypted file is located for this user //
            string encContainerLoc = (string)Registry.GetValue(Keenou.Config.LOCAL_MACHINE_REG_ROOT + sidString, "encContainerLoc", null);
            if (string.IsNullOrEmpty(encContainerLoc))
            {
                // Ensure system-defined home folder actually exists 
                if (!Directory.Exists(homeFolder) || !File.Exists(homeFolder + @"\" + "NTUSER.DAT"))
                {
                    return new BooleanResult() { Success = false, Message = "User's home folder not encrypted, but does not exist! " + homeFolder };
                }

                return new BooleanResult() { Success = true, Message = "User's home folder not encrypted." + homeFolder };
            }
            m_logger.InfoFormat("Encrypted container: {0}", encContainerLoc);
            // * //



            // Get and decrypt user's master key (using user password) //
            string masterKey = null;
            string encHeader = (string)Registry.GetValue(Keenou.Config.LOCAL_MACHINE_REG_ROOT + sidString, "encHeader", null);
            if (string.IsNullOrEmpty(encHeader))
            {
                return new BooleanResult() { Success = false, Message = "User's header information could not be found." };
            }
            m_logger.InfoFormat("Encrypted header: {0}", encHeader);

            try
            {
                masterKey = Keenou.AESGCM.SimpleDecryptWithPassword(encHeader, userInfo.Password);

                // Make sure we got a key back 
                if (masterKey == null)
                {
                    throw new Exception("Failed to decrypt master key!");
                }
            }
            catch (Exception err)
            {
                return new BooleanResult() { Success = false, Message = "Cannot obtain master key! " + err.Message };
            }
            // * //



            // Determine if this is the first boot (setup/migrate) //
            bool firstBoot = false;
            {
                object firstBoot_O = Registry.GetValue(Keenou.Config.LOCAL_MACHINE_REG_ROOT + sidString, "firstBoot", false);

                if (firstBoot_O == null)
                {
                    return new BooleanResult() { Success = false, Message = "Cannot obtain firstBoot value." };
                }

                firstBoot = Convert.ToBoolean(firstBoot_O);
            }
            // * //



            // If system-defined home folder exists and it's not first boot, assume ENC drive already set up // 
            if (!firstBoot && Directory.Exists(homeFolder) && File.Exists(homeFolder + @"\" + "NTUSER.DAT"))
            {
                return new BooleanResult() { Success = true, Message = "User's home folder already prepared." };
            }
            // * //



            // Get next free drive letter // 
            string targetDrive = Keenou.Toolbox.GetNextFreeDriveLetter();
            if (targetDrive == null)
            {
                return new BooleanResult() { Success = false, Message = "Failed to find a free drive letter." };
            }
            m_logger.InfoFormat("Free drive letter: {0}", targetDrive);
            // * //



            // Mount home drive //
            Keenou.BooleanResult res = Keenou.EncryptDirectory.MountEncryptedVolume(hashChosen, encContainerLoc, targetDrive, masterKey);
            if (!res.Success)
            {
                return new BooleanResult() { Success = false, Message = res.Message };
            }
            // * //




            // If first boot, we need to (finish) migrate old files over to ENC directory //
            if (firstBoot)
            {
                m_logger.InfoFormat("First boot for this user!");


                // Make sure old location exists (before moving files over to new location) 
                if (!Directory.Exists(homeFolder) || !File.Exists(homeFolder + @"\" + "NTUSER.DAT"))
                {
                    return new BooleanResult() { Success = false, Message = "Old home directory inaccessible." };
                }


                // TODO: save junction directories? (skipped by robocopy) 
                //dir /S /A:L


                // EXECUTE CMD (copy remaining files over to new encrypted container) 
                Process process = new Process();
                ProcessStartInfo startInfo = new ProcessStartInfo();
                try
                {
                    startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    startInfo.FileName = "cmd.exe";
                    startInfo.Arguments = "/C \"robocopy \"" + homeFolder + "\" " + targetDrive + ":\\ /zb /MIR /copyall /sl /xj /r:0\"";
                    process.StartInfo = startInfo;
                    process.Start(); // this may take a while! 
                    process.WaitForExit();

                    // Ensure no errors were thrown 
                    if (process.ExitCode > 7)
                    {
                        return new BooleanResult() { Success = false, Message = "Error while copying files over! " + process.ExitCode };
                    }

                }
                catch (Exception e)
                {
                    return new BooleanResult() { Success = false, Message = "Failed to finish moving home volume. " + e.Message };
                }


                // TODO: re-link junction directories? 



                // TODO: DELETE/SHRED OLD FOLDER 
                //rmdir /S /Q E:\Users
                Directory.Move(homeFolder, homeFolder + ".bakup");



                // Finished -- not firstBoot anymore! 
                try
                {
                    Registry.SetValue(Keenou.Config.LOCAL_MACHINE_REG_ROOT + sidString, "firstBoot", false, RegistryValueKind.DWord);
                }
                catch (Exception e)
                {
                    return new BooleanResult() { Success = false, Message = "Failed to change first boot registry setting. " + e.Message };
                }


                m_logger.InfoFormat("User's encrypted home volume successfully moved.");
            }
            // * //



            // Make sure new location exists and has user's registry hive //
            if (!Directory.Exists(targetDrive + @":\") || !File.Exists(targetDrive + @":\" + "NTUSER.DAT"))
            {
                return new BooleanResult() { Success = false, Message = "New home directory inaccessible or not fully set up." };
            }
            // * //



            // Update user home directory path in registry to mounted ENC drive //
            try
            {
                // REMOVED: Microsoft isn't happy when you try to move the User profile off of the system drive (junction instead) 
                //Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sidString, "ProfileImagePath", targetDrive + @":\");


                // Save where we mounted the encrypted volume 
                Registry.SetValue(Keenou.Config.LOCAL_MACHINE_REG_ROOT + sidString, "encDrive", targetDrive);


                // Remove old directory junction (if it's there) 
                if (Directory.Exists(homeFolder) && !File.Exists(homeFolder + @"\" + "NTUSER.DAT"))
                {
                    Directory.Delete(homeFolder, true);
                }


                // EXECUTE CMD (create directory junction from old location to new) 
                Process process = new Process();
                ProcessStartInfo startInfo = new ProcessStartInfo();
                try
                {
                    startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    startInfo.FileName = "cmd.exe";
                    startInfo.Arguments = "/C \"mklink /J \"" + homeFolder + "\" " + targetDrive + ":\\ \"";
                    process.StartInfo = startInfo;
                    process.Start();
                    process.WaitForExit();

                    // Ensure no errors were thrown 
                    if (process.ExitCode != 0)
                    {
                        return new BooleanResult() { Success = false, Message = "Error while creating directory junction!" };
                    }
                }
                catch (Exception e)
                {
                    return new BooleanResult() { Success = false, Message = "Failed to create directory junction. " + e.Message };
                }


            }
            catch (Exception e)
            {
                return new BooleanResult() { Success = false, Message = "Failed to finish moving home volume registry values. " + e.Message };
            }
            // * //



            // If we haven't failed by now, all should be good 
            return new BooleanResult() { Success = true, Message = "User logged in!" };
        }

    }
}