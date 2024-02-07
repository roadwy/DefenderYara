
rule Ransom_MSIL_RanserCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/RanserCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 6c 6f 63 6b 59 6f 75 72 46 69 6c 65 73 2e 4c 6f 67 69 6e } //01 00  UnlockYourFiles.Login
		$a_01_1 = {38 00 31 00 63 00 35 00 66 00 63 00 30 00 64 00 2d 00 33 00 64 00 64 00 64 00 2d 00 34 00 34 00 62 00 36 00 2d 00 38 00 31 00 30 00 65 00 2d 00 37 00 63 00 31 00 63 00 65 00 36 00 33 00 36 00 64 00 33 00 64 00 65 00 } //01 00  81c5fc0d-3ddd-44b6-810e-7c1ce636d3de
		$a_03_2 = {61 03 61 0a 7e 90 01 04 0d 09 06 93 0b 7e 90 01 04 07 9a 25 13 90 01 01 2c 03 90 00 } //01 00 
		$a_00_3 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 00 11 08 08 fe 04 2d da } //00 00 
	condition:
		any of ($a_*)
 
}