
rule Trojan_Win32_Shipup_GJU_MTB{
	meta:
		description = "Trojan:Win32/Shipup.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 89 45 fc 8b 4d d0 89 4d f0 8b 55 cc 89 55 f8 8b 45 cc 89 45 e0 8b 4d e0 8b 11 33 55 f0 8b 45 e0 89 10 } //10
		$a_01_1 = {00 c7 45 c8 35 dc 07 00 8b 55 ec 89 55 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}