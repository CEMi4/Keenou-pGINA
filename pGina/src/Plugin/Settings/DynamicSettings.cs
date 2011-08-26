﻿/*
	Copyright (c) 2011, pGina Team
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
		* Redistributions of source code must retain the above copyright
		  notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above copyright
		  notice, this list of conditions and the following disclaimer in the
		  documentation and/or other materials provided with the distribution.
		* Neither the name of the pGina Team nor the names of its contributors 
		  may be used to endorse or promote products derived from this software without 
		  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Dynamic;
using Microsoft.Win32;

namespace pGina.Shared.Settings
{
    public class DynamicSettings : DynamicObject
    {
        public static readonly string PGINA_KEY = @"SOFTWARE\pGina3";
        private string m_rootKey = PGINA_KEY;
        
        public DynamicSettings()
        {
        }

        public DynamicSettings(Guid pluginGuid)
        {
            m_rootKey = string.Format("{0}\\Plugins\\{1}", m_rootKey, pluginGuid.ToString());
        }

        public DynamicSettings(string root)
        {
            m_rootKey = root;
        }

        /// <summary>
        /// Sets the default value for a setting.  Checks to see if the setting
        /// is already defined in the registry.  If so, the method does nothing.
        /// Otherwise the setting is initialized to value.
        /// </summary>
        /// <param name="name">The name of the setting</param>
        /// <param name="value">The default value for the setting</param>
        public void SetDefault(string name, object value)
        {
            try
            {
                GetSetting(name);
            }
            catch (KeyNotFoundException)
            {
                SetSetting(name, value);
            }
        }

        public void SetSetting(string name, object value)
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(m_rootKey))
            {
                key.SetValue(name, value);
            }            
        }
        
        public override bool TrySetMember(SetMemberBinder binder, object value)
        {
            SetSetting(binder.Name, value);            
            return true;
        }

        public DynamicSetting GetSetting(string name)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(m_rootKey))
            {
                if (key != null && key.GetValueNames().Contains(name))
                {
                    object value = key.GetValue(name);
                    return new DynamicSetting(name, value);                    
                }
                else
                {
                    throw new KeyNotFoundException(string.Format("Unable to find value for: {0}", name));                    
                }
            }
        }

        public DynamicSetting GetSetting(string name, object def)
        {
            try
            {
                return GetSetting(name);
            }
            catch (KeyNotFoundException)
            {
                return new DynamicSetting(name, def);
            }
        }
        
        public override bool TryGetMember(GetMemberBinder binder, out object result)
        {            
            result = GetSetting(binder.Name);
            return true;            
        }       
    }    
}
