
rule Trojan_Win32_Mikey_LRD_MTB{
	meta:
		description = "Trojan:Win32/Mikey.LRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 07 00 00 "
		
	strings :
		$a_03_0 = {32 10 40 88 16 83 ef 01 75 ?? 8b 4c 24 20 4b 2b c5 46 } //20
		$a_81_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_81_2 = {68 74 74 70 3a 2f 2f 25 73 25 73 } //2 http://%s%s
		$a_81_3 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //3 SeDebugPrivilege
		$a_81_4 = {64 6f 77 6e 6c 6f 61 64 2d } //4 download-
		$a_81_5 = {75 70 64 61 74 65 2d } //5 update-
		$a_81_6 = {63 68 65 63 6b 69 6e 3a } //6 checkin:
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*4+(#a_81_5  & 1)*5+(#a_81_6  & 1)*6) >=41
 
}