
rule Trojan_Win32_Remcos_BSA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 86 93 0f 66 f9 09 0f 66 ba 02 0f 66 41 09 0f 66 74 a2 0d 66 6e 02 0f 66 06 03 0f 66 06 04 0f } //4
		$a_01_1 = {44 96 0f 66 11 dd 0e 66 00 00 00 00 00 00 00 00 01 00 08 00 96 59 40 00 } //4
		$a_01_2 = {66 ee 94 0f 66 ea 62 0f 66 74 9b 0c 66 f6 09 0f 66 87 9b 0c 66 93 95 0f 66 85 9a 0c 66 df 47 0e } //4
		$a_01_3 = {66 89 06 0f 66 ba 03 0f 66 13 75 10 66 2b 94 0f 66 37 a2 0d 66 3a 03 0f 66 3a 04 0f 66 6e 03 0f } //4
		$a_01_4 = {ff ff ff c1 ff ff fc 3c 7f ff c3 fc 1f f8 3f fc 07 fb ff fc 1f fb ff fc 7f fb ff fd ff fb ff fd } //2
		$a_01_5 = {ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff fd ff fb ff c1 ff fb fc 3d } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=20
 
}