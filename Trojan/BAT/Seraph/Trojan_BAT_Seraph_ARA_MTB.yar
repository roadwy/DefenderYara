
rule Trojan_BAT_Seraph_ARA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 16 11 04 8e 69 28 0d 00 00 0a } //02 00 
		$a_01_1 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //01 00  .edom SOD ni nur eb tonnac margorp sihT!
		$a_01_2 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_3 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}