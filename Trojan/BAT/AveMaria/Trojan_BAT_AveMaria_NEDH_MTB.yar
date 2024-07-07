
rule Trojan_BAT_AveMaria_NEDH_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {39 65 66 37 64 32 62 39 2d 30 64 66 32 2d 34 30 37 61 2d 61 36 61 35 2d 36 61 37 65 31 35 65 35 66 30 65 65 } //5 9ef7d2b9-0df2-407a-a6a5-6a7e15e5f0ee
		$a_01_1 = {59 61 68 74 7a 65 65 2e 46 56 55 4a 48 42 53 46 } //5 Yahtzee.FVUJHBSF
		$a_01_2 = {59 61 68 74 7a 65 65 20 53 63 6f 72 62 6f 61 72 64 } //2 Yahtzee Scorboard
		$a_01_3 = {4d 61 67 73 20 49 6e 64 75 73 74 72 69 65 73 } //2 Mags Industries
		$a_01_4 = {4d 4d 20 4c 69 6e 67 6e 61 75 20 20 32 30 31 33 } //2 MM Lingnau  2013
		$a_01_5 = {49 74 20 69 73 20 61 20 67 61 6d 65 20 70 6c 61 79 65 64 20 77 69 74 68 20 35 20 64 69 63 65 20 61 6e 64 20 67 6f 6f 64 20 66 72 69 65 6e 64 73 } //2 It is a game played with 5 dice and good friends
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=18
 
}