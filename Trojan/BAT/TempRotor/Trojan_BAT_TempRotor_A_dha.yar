
rule Trojan_BAT_TempRotor_A_dha{
	meta:
		description = "Trojan:BAT/TempRotor.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 6b 27 14 8a ac ba 41 a7 0b 95 78 18 43 a9 e4 } //100
		$a_01_1 = {9f 2a e2 60 86 28 ed 46 8f fa a0 80 bf 10 5d cf } //100
		$a_01_2 = {3d 5d cd c1 f4 53 5d 45 87 02 38 4d 49 45 37 bd } //100
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=100
 
}