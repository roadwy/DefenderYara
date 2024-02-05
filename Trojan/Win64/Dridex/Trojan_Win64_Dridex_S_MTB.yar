
rule Trojan_Win64_Dridex_S_MTB{
	meta:
		description = "Trojan:Win64/Dridex.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 03 00 "
		
	strings :
		$a_80_0 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  03 00 
		$a_80_1 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  03 00 
		$a_80_2 = {63 63 70 6c 65 72 2e 70 64 62 } //ccpler.pdb  03 00 
		$a_80_3 = {53 65 74 49 43 4d 4d 6f 64 65 } //SetICMMode  03 00 
		$a_80_4 = {4e 64 72 43 6c 65 61 72 4f 75 74 50 61 72 61 6d 65 74 65 72 73 } //NdrClearOutParameters  00 00 
	condition:
		any of ($a_*)
 
}