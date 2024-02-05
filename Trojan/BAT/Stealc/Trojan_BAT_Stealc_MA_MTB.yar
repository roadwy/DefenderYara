
rule Trojan_BAT_Stealc_MA_MTB{
	meta:
		description = "Trojan:BAT/Stealc.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 03 28 1d 00 00 06 0a de 0a 26 16 8d 34 00 00 01 0a de 00 06 2a } //02 00 
		$a_01_1 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}