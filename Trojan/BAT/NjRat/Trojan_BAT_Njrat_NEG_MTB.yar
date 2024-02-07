
rule Trojan_BAT_Njrat_NEG_MTB{
	meta:
		description = "Trojan:BAT/Njrat.NEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {6e 41 4e 23 74 39 52 } //03 00  nAN#t9R
		$a_01_1 = {7a 76 61 57 76 37 73 6b } //03 00  zvaWv7sk
		$a_01_2 = {76 73 56 6c 6c 78 4a } //02 00  vsVllxJ
		$a_01_3 = {45 7b 30 6c 54 69 4e 67 } //01 00  E{0lTiNg
		$a_01_4 = {57 69 6e 64 6f 77 73 2e 65 78 65 } //01 00  Windows.exe
		$a_01_5 = {6d 6b 68 57 66 65 } //01 00  mkhWfe
		$a_01_6 = {7a 78 61 34 76 47 73 } //00 00  zxa4vGs
	condition:
		any of ($a_*)
 
}