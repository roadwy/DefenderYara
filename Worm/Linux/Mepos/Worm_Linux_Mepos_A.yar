
rule Worm_Linux_Mepos_A{
	meta:
		description = "Worm:Linux/Mepos.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_02_0 = {0f e0 a0 11 05 f0 a0 11 37 3c e0 e3 f3 30 23 e2 00 40 93 e5 ?? ?? ?? ?? 00 00 54 e1 40 00 9f 15 00 e0 a0 13 00 30 a0 13 00 20 a0 13 00 10 a0 13 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 55 e3 ?? ?? 9d 05 ?? ?? 9d 05 ?? ?? ?? ?? 06 10 a0 e1 42 00 a0 e3 ?? ?? ?? ?? 00 00 e0 e3 } //4
		$a_00_1 = {68 74 74 70 3a 2f 2f 6d 6f 62 69 2e 78 69 61 6f 6d 65 69 74 69 2e 63 6f 6d 2f 75 70 6c 6f 61 64 66 69 6c 65 2f 6d 73 65 72 76 69 63 65 32 2e 7a 69 70 } //2 http://mobi.xiaomeiti.com/uploadfile/mservice2.zip
		$a_00_2 = {25 73 3f 69 6d 65 69 3d 25 73 26 4d 61 6a 6f 72 56 65 72 73 69 6f 6e 3d 25 64 26 4d 69 6e 6f 72 56 65 72 73 69 6f 6e 3d 25 64 26 42 75 69 6c 64 4e 75 6d 62 65 72 3d 25 64 26 57 69 64 74 68 3d 25 64 26 48 69 67 68 74 3d 25 64 26 54 6f 74 61 6c 50 68 79 73 3d 25 64 26 55 49 4c 61 6e 67 75 61 67 65 3d 25 64 26 4c 61 6e 67 49 44 3d 25 64 26 6d 6f 64 65 6c 3d 25 73 26 70 6c 61 74 66 6f 72 6d 3d 25 73 } //2 %s?imei=%s&MajorVersion=%d&MinorVersion=%d&BuildNumber=%d&Width=%d&Hight=%d&TotalPhys=%d&UILanguage=%d&LangID=%d&model=%s&platform=%s
		$a_00_3 = {68 74 74 70 3a 2f 2f 6d 6f 62 69 2e 78 69 61 6f 6d 65 69 74 69 2e 63 6f 6d 2f 75 70 64 61 74 65 69 6d 65 69 } //2 http://mobi.xiaomeiti.com/updateimei
		$a_00_4 = {25 73 3f 6d 76 3d 25 64 26 69 6d 73 69 3d 25 73 26 69 6d 65 69 3d 25 73 26 62 75 69 6c 64 3d 25 64 26 74 79 70 65 3d 25 64 26 6f 77 6e 65 72 3d 25 73 } //2 %s?mv=%d&imsi=%s&imei=%s&build=%d&type=%d&owner=%s
		$a_00_5 = {5c 57 69 6e 64 6f 77 73 5c 6d 73 73 2e 7a 69 70 } //1 \Windows\mss.zip
		$a_00_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_00_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_80_8 = {5c 25 73 5c 32 35 37 37 5c 61 75 74 6f 72 75 6e 2e 65 78 65 } //\%s\2577\autorun.exe  1
		$a_80_9 = {5c 53 65 63 75 72 69 74 79 5c 50 6f 6c 69 63 69 65 73 5c 50 6f 6c 69 63 69 65 73 } //\Security\Policies\Policies  1
		$a_80_10 = {5c 5c 2e 5c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 5c 4e 61 6d 65 64 45 76 65 6e 74 73 5c 41 70 70 52 75 6e 41 74 4e 65 74 43 6f 6e 6e 65 63 74 } //\\.\Notifications\NamedEvents\AppRunAtNetConnect  1
		$a_80_11 = {49 50 4d 2e 53 4d 53 74 65 78 74 } //IPM.SMStext  1
		$a_80_12 = {47 50 52 53 20 44 65 76 69 63 65 20 46 69 6e 64 65 72 } //GPRS Device Finder  1
	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=10
 
}