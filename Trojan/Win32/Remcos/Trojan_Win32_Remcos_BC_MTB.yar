
rule Trojan_Win32_Remcos_BC_MTB{
	meta:
		description = "Trojan:Win32/Remcos.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 a1 90 01 04 8b 08 8b 15 90 01 04 8b 04 91 2d 90 01 03 00 89 45 fc 8b 0d 90 01 04 83 c1 01 89 0d 90 01 04 8b 45 fc 8b e5 5d c3 90 00 } //1
		$a_03_1 = {ff d7 8d 54 24 10 8b f8 33 f6 89 15 90 01 04 b3 90 01 01 e8 90 01 02 ff ff 0f bf 0d 90 01 04 39 0d 90 01 04 7c 90 01 01 88 1d 90 01 04 88 04 3e 83 c6 01 81 fe 90 01 02 00 00 7c 90 00 } //1
		$a_03_2 = {6e c6 44 24 90 01 01 32 c6 44 24 90 01 01 6f c6 44 24 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}