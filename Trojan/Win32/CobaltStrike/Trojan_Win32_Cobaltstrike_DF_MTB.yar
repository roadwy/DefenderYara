
rule Trojan_Win32_Cobaltstrike_DF_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4b 04 8b c9 8b c7 8b 55 0c 8b c0 c1 e1 02 2b c1 8a 04 10 32 06 88 04 3a 8b c9 8b c7 8b 4b 04 c1 e1 02 8b c9 2b c1 8a 44 10 01 8b c0 32 46 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Cobaltstrike_DF_MTB_2{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 07 89 7d f8 8b 7d fc 88 04 3e 8b c7 8b 7d f8 88 0c 07 0f b6 04 06 8b 4d fc 03 c2 8b 7d f4 0f b6 c0 8a 04 08 32 04 1f 88 03 43 83 6d 0c 01 8b c1 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}