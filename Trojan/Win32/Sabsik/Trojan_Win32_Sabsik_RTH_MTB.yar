
rule Trojan_Win32_Sabsik_RTH_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_81_0 = {69 33 38 36 5c 63 68 6b 65 73 70 2e 63 } //10 i386\chkesp.c
		$a_81_1 = {44 3a 5c 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 2e 70 64 62 } //10 D:\4234234234234234234234234234.pdb
		$a_81_2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //1 GetStartupInfoA
		$a_81_3 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 57 } //1 GetLocaleInfoW
		$a_81_4 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //1 GetSystemInfo
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=23
 
}