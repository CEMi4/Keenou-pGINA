using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using pGina.Shared.Types;
using Microsoft.Win32;
using System.Security.Principal;
using System.Diagnostics;
using System.IO;
using log4net;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

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



        // Get SHA-512 signature from input text //
        public static string SHA512_Base64(string input)
        {
            using (SHA512 alg = SHA512.Create())
            {
                byte[] result = alg.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(result);
            }
        }
        // * //


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
            string hashChosen = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Keenou\" + sidString, "hash", "whirlpool");
            if (string.IsNullOrEmpty(hashChosen))
            {
                return new BooleanResult() { Success = false, Message = "Cannot find user's hash algorithm in registry." };
            }
            m_logger.InfoFormat("Hash algorithm: {0}", hashChosen);
            // * //



            // Figure out where the home folder's encrypted file is located for this user //
            string encContainerLoc = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Keenou\" + sidString, "encContainerLoc", null);
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



            // Determine if this is the first boot (setup/migrate) //
            bool firstBoot = false;
            {
                object firstBoot_O = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Keenou\" + sidString, "firstBoot", false);

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



            // Mount home folder's encrypted file as targetDrive //
            string targetDrive = null;
            using (Process process = new Process())
            {

                // GET NEXT FREE DRIVE LETTER 
                char[] alpha = "VTHEDFGIJKLMNOPQRSUWXYZC".ToCharArray();
                string[] taken = Directory.GetLogicalDrives();
                foreach (char dL in alpha)
                {
                    int pos = Array.IndexOf(taken, dL + @":\");
                    if (pos == -1)
                    {
                        targetDrive = dL.ToString();
                        break;
                    }
                }
                if (targetDrive == null)
                {
                    return new BooleanResult() { Success = false, Message = "Failed to find a free drive letter. " + String.Join(",", taken) };
                }
                m_logger.InfoFormat("Free drive letter: {0}", targetDrive);


                // GET VeraCrypt DIRECTORY
                string programDir = (Environment.GetEnvironmentVariable("PROGRAMFILES(X86)") ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)) + @"\VeraCrypt\";
                m_logger.InfoFormat("Location of Veracrypt executables: {0}", programDir);


                // Make sure veracrypt is installed
                if (!Directory.Exists(programDir))
                {
                    return new BooleanResult() { Success = false, Message = "VeraCrypt inaccessible." };
                }


                // MOUNT ENCRYPTED CONTAINER (TODO: sanitize password?)
                ProcessStartInfo startInfo = new ProcessStartInfo();
                try
                {
                    //.\"VeraCrypt Format.exe" /create test.hc /password testing /size 10M /hash whirlpool /encryption AES(Twofish(Serpent)) /filesystem NTFS /force /silent

                    startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    startInfo.FileName = "cmd.exe";
                    startInfo.Arguments = "/C \"\"" + programDir + "VeraCrypt.exe\" /hash " + hashChosen + " /v \"" + encContainerLoc + "\" /l " + targetDrive + " /f /h n /p \"" + SHA512_Base64(userInfo.Password) + "\" /q /s\"";
                    process.StartInfo = startInfo;
                    process.Start();
                    process.WaitForExit();

                    // Ensure no errors were thrown 
                    if (process.ExitCode != 0)
                    {
                        return new BooleanResult() { Success = false, Message = "Error while mounting encrypted file!" };
                    }

                    //m_logger.InfoFormat("CMD Argument: {0}", startInfo.Arguments);
                }
                catch (Exception e)
                {
                    return new BooleanResult() { Success = false, Message = "Failed to mount encrypted home volume. " + e.Message };
                }

            }
            // * //



            // Make sure encrypted system was mounted //
            if (!Directory.Exists(targetDrive + @":\"))
            {
                return new BooleanResult() { Success = false, Message = "Failed to mount encrypted home volume." };
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
                    startInfo.Arguments = "/C \"robocopy \"" + homeFolder + "\" " + targetDrive + ":\\ /MIR /copyall /sl /xj /r:0\"";
                    process.StartInfo = startInfo;
                    process.Start(); // this may take a while! 
                    process.WaitForExit();

                    // Ensure no errors were thrown 
                    if (process.ExitCode >= 4)
                    {
                        return new BooleanResult() { Success = false, Message = "Error while copying files over!" };
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
                    Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Keenou\" + sidString, "firstBoot", false, RegistryValueKind.DWord);
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