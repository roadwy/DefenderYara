
rule Trojan_BAT_Ursu_A_MTB{
	meta:
		description = "Trojan:BAT/Ursu.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {26 20 84 79 20 71 20 e9 23 76 19 61 25 fe 0e 01 00 20 0a 90 01 03 5e 90 00 } //10
		$a_80_1 = {47 69 61 6e 74 6d 61 73 74 65 72 } //Giantmaster  3
		$a_80_2 = {54 68 6f 75 73 61 6e 64 69 6e 74 6f } //Thousandinto  3
		$a_80_3 = {4a 6f 62 64 69 66 66 65 72 65 6e 63 65 } //Jobdifference  3
		$a_80_4 = {47 72 65 77 41 73 6b } //GrewAsk  3
		$a_80_5 = {53 65 65 69 6e 67 73 68 65 65 74 } //Seeingsheet  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=15
 
}