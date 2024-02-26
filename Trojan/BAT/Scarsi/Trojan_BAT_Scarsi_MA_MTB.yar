
rule Trojan_BAT_Scarsi_MA_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 0c 16 0d 08 12 03 28 19 00 00 0a 06 07 02 07 18 6f 1a 00 00 0a 1f 10 28 1b 00 00 0a 6f 1c 00 00 0a de 0a } //02 00 
		$a_01_1 = {53 68 75 74 64 6f 77 6e 73 } //02 00  Shutdowns
		$a_01_2 = {49 6e 74 65 72 72 75 70 74 65 64 } //00 00  Interrupted
	condition:
		any of ($a_*)
 
}