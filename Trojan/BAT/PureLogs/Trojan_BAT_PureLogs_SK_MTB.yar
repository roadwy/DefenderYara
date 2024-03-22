
rule Trojan_BAT_PureLogs_SK_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 8d 17 00 00 01 13 05 11 04 11 05 16 09 6f 13 00 00 0a 26 11 05 28 01 00 00 2b 28 02 00 00 2b 0a de 16 } //00 00 
	condition:
		any of ($a_*)
 
}