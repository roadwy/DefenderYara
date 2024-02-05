
rule Trojan_BAT_Redcap_AR_MTB{
	meta:
		description = "Trojan:BAT/Redcap.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {25 16 1f 7c 9d 6f 90 01 03 0a 16 9a 13 06 11 06 17 8d 90 01 01 00 00 01 25 16 1f 20 9d 6f 90 01 03 0a 16 9a 6f 90 01 03 0a 13 18 11 06 11 18 90 00 } //01 00 
		$a_01_1 = {5c 50 43 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 74 65 61 6c 65 72 20 74 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}