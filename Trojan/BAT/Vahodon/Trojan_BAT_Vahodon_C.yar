
rule Trojan_BAT_Vahodon_C{
	meta:
		description = "Trojan:BAT/Vahodon.C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6e 00 6a 00 2d 00 71 00 38 00 } //01 00 
		$a_00_1 = {69 00 6e 00 66 00 6f 00 7c 00 7c 00 6d 00 79 00 49 00 44 00 7c 00 7c 00 } //01 00 
		$a_00_2 = {6f 00 70 00 65 00 6e 00 75 00 72 00 6c 00 } //01 00 
		$a_00_3 = {73 00 65 00 6e 00 64 00 66 00 69 00 6c 00 65 00 } //01 00 
		$a_01_4 = {6b 6f 6e 65 6b } //00 00 
		$a_00_5 = {5d 04 00 } //00 d3 
	condition:
		any of ($a_*)
 
}