
rule Trojan_Win32_RemcosRAT_BSA_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 e8 18 0c fb ff 83 f8 01 1b c0 40 84 c0 0f 84 98 00 00 00 b3 01 83 } //10
		$a_81_1 = {41 6d 73 69 49 6e 69 74 69 61 6c 69 7a 65 } //1 AmsiInitialize
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}
rule Trojan_Win32_RemcosRAT_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/RemcosRAT.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 73 00 73 00 75 00 72 00 65 00 72 00 20 00 67 00 65 00 6e 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 65 00 73 } //12
		$a_01_1 = {73 00 69 00 66 00 74 00 65 00 72 00 20 00 73 00 6b 00 61 00 6b 00 6b 00 65 00 72 00 6e 00 65 00 73 } //8
	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8) >=20
 
}