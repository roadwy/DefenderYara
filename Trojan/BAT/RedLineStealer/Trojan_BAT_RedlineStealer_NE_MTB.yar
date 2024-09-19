
rule Trojan_BAT_RedlineStealer_NE_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 0d 11 08 17 58 13 08 11 08 07 8e 69 } //3
		$a_01_1 = {11 06 17 58 13 06 11 06 06 8e 69 07 8e 69 59 } //3
		$a_81_2 = {39 41 30 36 36 38 41 41 2d 32 45 37 46 2d 34 46 46 44 2d 41 36 39 30 2d 32 31 44 35 33 43 46 39 39 39 39 39 } //4 9A0668AA-2E7F-4FFD-A690-21D53CF99999
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_81_2  & 1)*4) >=10
 
}