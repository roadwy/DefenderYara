
rule Trojan_BAT_Dnoper_ADN_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.ADN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {a2 25 17 08 a2 25 18 72 e7 0e 00 70 a2 25 19 02 7b 12 00 00 04 a2 25 1a 72 17 0f 00 70 a2 28 28 00 00 0a 13 04 09 11 04 28 } //00 00 
	condition:
		any of ($a_*)
 
}