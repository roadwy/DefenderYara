
rule Spyware_Win32_Look2Me{
	meta:
		description = "Spyware:Win32/Look2Me,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 6f 6b 32 6d 65 2e 63 6f 6d 2f } //10 http://www.look2me.com/
		$a_00_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_00_2 = {55 73 65 72 2d 41 67 65 6e 74 3a } //10 User-Agent:
		$a_01_3 = {44 45 54 45 43 54 52 45 47 55 53 45 52 53 } //10 DETECTREGUSERS
		$a_00_4 = {4c 6f 6f 6b 32 4d 65 5f 43 6c 61 73 73 } //1 Look2Me_Class
		$a_00_5 = {4e 65 6f 53 6f 66 74 5f 43 6c 61 73 73 } //1 NeoSoft_Class
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=41
 
}
rule Spyware_Win32_Look2Me_2{
	meta:
		description = "Spyware:Win32/Look2Me,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 25 73 5c 49 6d 70 6c 65 6d 65 6e 74 65 64 20 43 61 74 65 67 6f 72 69 65 73 5c 7b 30 30 30 32 31 34 39 32 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d } //3 CLSID\%s\Implemented Categories\{00021492-0000-0000-C000-000000000046}
		$a_01_1 = {61 64 5f 43 6c 61 73 73 } //1 ad_Class
		$a_01_2 = {44 65 73 6b 62 61 6e 64 } //1 Deskband
		$a_01_3 = {41 64 53 65 72 76 65 72 } //1 AdServer
		$a_01_4 = {73 65 6e 64 45 78 74 65 72 6e 61 6c 55 72 6c } //1 sendExternalUrl
		$a_01_5 = {73 65 6e 64 45 78 74 65 72 6e 61 6c 45 76 65 6e 74 } //1 sendExternalEvent
		$a_01_6 = {77 77 77 2e 61 64 2d 77 2d 61 2d 72 2d 65 2e 63 6f 6d } //2 www.ad-w-a-r-e.com
		$a_01_7 = {77 77 77 2e 61 2d 64 2d 77 2d 61 2d 72 2d 65 2e 63 6f 6d } //2 www.a-d-w-a-r-e.com
		$a_01_8 = {68 74 74 70 3a 2f 2f 25 73 2f 41 44 2f 55 43 4d 44 3f } //3 http://%s/AD/UCMD?
		$a_01_9 = {68 74 74 70 3a 2f 2f 25 73 2f 41 44 2f 43 4d 44 3f } //3 http://%s/AD/CMD?
		$a_01_10 = {4e 69 63 54 65 63 68 20 4e 65 74 77 6f 72 6b 73 } //3 NicTech Networks
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3) >=15
 
}
rule Spyware_Win32_Look2Me_3{
	meta:
		description = "Spyware:Win32/Look2Me,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 53 69 6d 70 6c 79 20 53 75 70 65 72 20 53 6f 66 74 77 61 72 65 5c 54 72 6f 6a 61 6e 20 52 65 6d 6f 76 65 72 5c } //-100 \Simply Super Software\Trojan Remover\
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {61 64 2d 77 2d 61 2d 72 2d 65 2e 63 6f 6d } //1 ad-w-a-r-e.com
		$a_00_3 = {72 6d 76 74 72 6a 61 6e 2e 65 78 65 } //1 rmvtrjan.exe
		$a_00_4 = {74 72 75 70 64 2e 65 78 65 } //1 trupd.exe
		$a_00_5 = {73 69 6d 70 6c 79 73 75 70 2e 63 6f 6d } //1 simplysup.com
		$a_00_6 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects
		$a_00_7 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_00_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41 } //1 URLDownloadToCacheFileA
	condition:
		((#a_01_0  & 1)*-100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=8
 
}
rule Spyware_Win32_Look2Me_4{
	meta:
		description = "Spyware:Win32/Look2Me,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 74 72 65 61 6d 73 5c 44 65 73 6b 74 6f 70 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\Desktop
		$a_01_1 = {43 4c 53 49 44 5c 25 73 5c 49 6d 70 6c 65 6d 65 6e 74 65 64 20 43 61 74 65 67 6f 72 69 65 73 5c 7b 30 30 30 32 31 34 39 32 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d } //3 CLSID\%s\Implemented Categories\{00021492-0000-0000-C000-000000000046}
		$a_01_2 = {43 4c 53 49 44 5c 7b 44 44 46 46 41 37 35 41 2d 45 38 31 44 2d 34 34 35 34 2d 38 39 46 43 2d 42 39 46 44 30 36 33 31 45 37 32 35 7d } //2 CLSID\{DDFFA75A-E81D-4454-89FC-B9FD0631E725}
		$a_01_3 = {25 73 6d 73 67 25 64 2e 64 6c 6c } //1 %smsg%d.dll
		$a_01_4 = {50 41 52 54 4e 45 52 49 44 } //1 PARTNERID
		$a_01_5 = {47 75 61 72 64 69 61 6e } //1 Guardian
		$a_01_6 = {7b 44 44 46 46 41 37 35 41 2d 45 38 31 44 2d 34 34 35 34 2d 38 39 46 43 2d 42 39 46 44 30 36 33 31 45 37 32 38 7d } //2 {DDFFA75A-E81D-4454-89FC-B9FD0631E728}
		$a_01_7 = {4e 49 43 54 45 43 48 20 4e 45 54 57 4f 52 4b 53 20 4c 4c 43 20 28 74 68 65 20 } //5 NICTECH NETWORKS LLC (the 
		$a_01_8 = {77 77 77 2e 6e 69 63 74 65 63 68 6e 65 74 77 6f 72 6b 73 2e 63 6f 6d 2f 65 75 6c 61 2e 68 74 6d 6c 20 20 42 79 20 63 6f 6e 74 69 6e 75 69 6e 67 20 74 6f 20 75 73 65 20 74 68 65 20 53 4f 46 54 57 41 52 45 20 50 52 4f 44 55 43 54 20 61 66 74 65 72 20 74 68 65 20 45 55 4c 41 20 69 73 20 } //5 www.nictechnetworks.com/eula.html  By continuing to use the SOFTWARE PRODUCT after the EULA is 
		$a_01_9 = {41 44 57 41 52 45 20 61 70 70 6c 69 63 61 74 69 6f 6e 5c 43 6f 72 65 5c 44 65 76 5c 49 6e 73 74 61 6c 6c 65 72 5c 52 65 6c 65 61 73 65 5c 49 6e 73 74 61 6c 6c 2e 70 64 62 } //5 ADWARE application\Core\Dev\Installer\Release\Install.pdb
		$a_01_10 = {4d 00 79 00 42 00 61 00 6e 00 64 00 73 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 } //3 MyBands Installer
		$a_01_11 = {49 00 20 00 41 00 63 00 63 00 65 00 70 00 74 00 } //1 I Accept
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*3+(#a_01_11  & 1)*1) >=12
 
}