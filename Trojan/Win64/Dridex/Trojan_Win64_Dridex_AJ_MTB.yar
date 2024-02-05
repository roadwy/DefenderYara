
rule Trojan_Win64_Dridex_AJ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {66 66 70 67 67 6c 62 6d 2e 70 64 62 } //ffpgglbm.pdb  03 00 
		$a_80_1 = {79 66 61 6d 69 6c 79 6a 62 72 6f 77 73 65 72 73 49 72 6f 6e 2c 39 74 6f 33 75 6e 64 65 72 } //yfamilyjbrowsersIron,9to3under  03 00 
		$a_80_2 = {6c 75 63 6b 79 69 6e 63 6f 67 6e 69 74 6f 77 61 73 69 73 6d 61 72 6c 62 6f 72 6f 65 } //luckyincognitowasismarlboroe  03 00 
		$a_80_3 = {74 68 65 69 6e 73 71 73 65 70 61 72 61 74 65 6c 79 2e 64 35 32 36 2c 43 53 53 52 68 } //theinsqseparately.d526,CSSRh  03 00 
		$a_80_4 = {4a 42 48 63 6f 6d 70 61 6e 79 2c 70 6c 61 79 65 72 2c 63 61 6e } //JBHcompany,player,can  03 00 
		$a_80_5 = {73 6f 68 69 64 64 65 6e 38 39 2e 37 35 25 4a 75 6e 65 6e 6f 72 6d 61 6c } //sohidden89.75%Junenormal  03 00 
		$a_80_6 = {62 6f 75 6e 64 61 72 79 66 6f 72 65 33 2e 30 6e 76 65 72 73 69 6f 6e 73 6e 65 77 73 } //boundaryfore3.0nversionsnews  00 00 
	condition:
		any of ($a_*)
 
}