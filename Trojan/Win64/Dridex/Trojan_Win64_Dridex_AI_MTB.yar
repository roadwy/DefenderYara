
rule Trojan_Win64_Dridex_AI_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {46 62 6e 6d 76 6c 2e 70 64 62 } //Fbnmvl.pdb  03 00 
		$a_80_1 = {55 36 6d 23 52 36 6d } //U6m#R6m  03 00 
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  03 00 
		$a_80_3 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  03 00 
		$a_80_4 = {4e 64 72 43 6c 65 61 72 4f 75 74 50 61 72 61 6d 65 74 65 72 73 } //NdrClearOutParameters  03 00 
		$a_80_5 = {53 65 74 49 43 4d 4d 6f 64 65 } //SetICMMode  03 00 
		$a_80_6 = {25 52 3a 20 70 33 } //%R: p3  00 00 
	condition:
		any of ($a_*)
 
}