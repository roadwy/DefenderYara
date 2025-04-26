
rule Trojan_Win32_Zusy_RJ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 03 4d e4 0f be 11 0f be 45 14 33 d0 88 55 eb 8b 4d e4 83 c1 01 89 4d e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 41 02 00 00 c7 45 fc 03 1b 00 00 8b 45 f4 03 45 fc 89 45 f4 c7 45 f0 00 00 00 00 8b 4d fc 03 4d f4 89 4d fc 8b 55 f0 2b 55 f4 89 55 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8d 54 24 10 8b c1 c1 e8 03 c1 e1 05 0b c1 f7 d0 89 44 24 14 } //5
		$a_01_1 = {33 34 66 34 62 63 62 63 64 34 39 63 37 63 64 34 36 63 38 65 38 63 38 34 39 36 62 34 37 63 38 65 38 34 36 63 63 34 } //1 34f4bcbcd49c7cd46c8e8c8496b47c8e846cc4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Zusy_RJ_MTB_4{
	meta:
		description = "Trojan:Win32/Zusy.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 65 72 76 65 72 2e 30 35 36 39 2e 6d 69 63 72 6f 73 6f 66 74 6d 69 64 64 6c 65 6e 61 6d 65 2e 74 6b } //3 http://server.0569.microsoftmiddlename.tk
		$a_01_1 = {68 74 74 70 3a 2f 2f 69 6d 67 63 61 63 68 65 2e 63 6c 6f 75 64 73 65 72 76 69 63 65 73 64 65 76 63 2e 74 6b } //2 http://imgcache.cloudservicesdevc.tk
		$a_01_2 = {50 72 6f 67 72 61 6d 44 61 74 61 2f 73 65 74 74 69 6e 67 2e 69 6e 69 } //1 ProgramData/setting.ini
		$a_01_3 = {48 69 70 73 54 72 61 79 2e 65 78 65 } //1 HipsTray.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}