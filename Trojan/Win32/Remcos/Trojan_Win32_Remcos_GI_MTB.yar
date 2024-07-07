
rule Trojan_Win32_Remcos_GI_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64 } //1
		$a_01_1 = {44 00 56 00 43 00 4c 00 41 00 4c } //1
		$a_01_2 = {48 00 41 00 4e 00 41 00 4d 00 53 00 49 00 4f } //1
		$a_81_3 = {52 54 4c 43 6f 6e 73 74 73 } //1 RTLConsts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}