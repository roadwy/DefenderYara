
rule Trojan_BAT_Zusy_ARR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 2b 01 17 0b 07 2c 0a 00 16 80 ?? ?? ?? ?? 00 2b 10 00 02 16 9a } //10
		$a_03_1 = {02 03 04 05 59 18 59 28 ?? ?? ?? ?? 00 00 2b 77 02 } //6
		$a_81_2 = {3c 4d 61 69 6e 54 68 72 65 61 64 3e 62 5f 5f 35 31 30 5f 31 30 } //4 <MainThread>b__510_10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*6+(#a_81_2  & 1)*4) >=20
 
}