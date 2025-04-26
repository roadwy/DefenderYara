
rule Trojan_Win32_ManBat_AF_MTB{
	meta:
		description = "Trojan:Win32/ManBat.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2a ef 4d 4a be 76 06 9e 5f c5 36 15 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 } //1
		$a_01_1 = {42 4c 74 4a 48 77 44 44 4d 48 55 42 52 49 73 4f 57 75 4a 55 } //1 BLtJHwDDMHUBRIsOWuJU
		$a_01_2 = {4d 57 49 42 41 4e 71 4f 45 43 42 79 4a 69 50 5a 4f 51 4c 55 } //1 MWIBANqOECByJiPZOQLU
		$a_01_3 = {6f 67 71 56 48 43 56 61 4b 53 6f 42 70 55 46 4a 43 50 54 6f } //1 ogqVHCVaKSoBpUFJCPTo
		$a_01_4 = {56 00 4f 00 72 00 4a 00 31 00 38 00 35 00 56 00 4f 00 72 00 4a 00 32 00 30 00 30 00 56 00 4f 00 72 00 4a 00 32 00 30 00 30 00 56 00 4f 00 72 00 4a 00 31 00 38 00 38 00 56 00 4f 00 72 00 4a 00 31 00 38 00 35 00 56 00 4f 00 72 00 4a 00 32 00 30 00 34 00 56 00 4f 00 72 00 4a 00 31 00 38 00 35 00 56 00 4f 00 72 00 4a 00 } //1 VOrJ185VOrJ200VOrJ200VOrJ188VOrJ185VOrJ204VOrJ185VOrJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}