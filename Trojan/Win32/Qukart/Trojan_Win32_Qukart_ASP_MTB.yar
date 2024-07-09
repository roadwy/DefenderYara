
rule Trojan_Win32_Qukart_ASP_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 44 90 82 7e 91 2b 1b 48 2f 2c 4b 11 e3 1a 13 21 e3 7c } //5
		$a_01_1 = {55 89 e5 81 ec f0 01 00 00 53 56 57 bb b3 17 c6 3b 89 d8 01 d8 89 c3 83 a5 } //5
		$a_03_2 = {1d 8b 00 e3 84 b6 3c 33 4b 8b 8b d6 3d 5b 42 e3 fa 2e 8d de 35 [0-04] b6 34 33 4b 8b 59 bc 57 74 54 6c 0d d6 5e 68 54 } //5
		$a_03_3 = {b8 a2 ab 0a dc 01 68 0a 89 88 [0-04] fc 81 81 [0-04] 73 cc 83 2c 30 5b 83 1a 82 [0-04] 54 7f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5) >=5
 
}