
rule Trojan_Win32_Formbook_MH_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 cc 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 ba 04 00 00 00 c1 e2 00 8b 45 cc 8b 0c 10 51 ff } //1
		$a_01_1 = {0f b6 11 83 c2 3a 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f b6 11 81 f2 86 00 00 00 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}