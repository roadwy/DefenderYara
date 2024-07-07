
rule Trojan_Win32_Cionrox_A{
	meta:
		description = "Trojan:Win32/Cionrox.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 22 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 22 3d 22 68 74 74 70 3a 2f 2f 25 6f 6b 25 2f 70 72 6f 78 79 2e 70 61 63 22 20 3e 3e 20 69 65 63 66 67 31 2e 72 65 67 } //1 echo "AutoConfigURL"="http://%ok%/proxy.pac" >> iecfg1.reg
		$a_01_1 = {65 63 68 6f 20 75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c 20 22 68 74 74 70 3a 2f 2f 25 6f 6b 25 2f 70 72 6f 78 79 2e 70 61 63 22 29 3b } //1 echo user_pref("network.proxy.autoconfig_url", "http://%ok%/proxy.pac");
		$a_01_2 = {44 4f 20 65 63 68 6f 20 67 72 61 6e 74 20 7b 20 20 70 65 72 6d 69 73 73 69 6f 6e 20 6a 61 76 61 2e 73 65 63 75 72 69 74 79 2e 41 6c 6c 50 65 72 6d 69 73 73 69 6f 6e } //1 DO echo grant {  permission java.security.AllPermission
		$a_01_3 = {72 65 67 20 61 64 64 20 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}