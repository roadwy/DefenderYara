
rule Trojan_BAT_Njrat_MVT_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 02 28 0f 00 00 06 0d de 16 } //01 00 
		$a_02_1 = {48 65 61 72 74 90 02 0f 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}