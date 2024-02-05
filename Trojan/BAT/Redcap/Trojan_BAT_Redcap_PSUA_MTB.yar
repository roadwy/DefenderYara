
rule Trojan_BAT_Redcap_PSUA_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 25 00 00 0a 14 17 8d 11 00 00 01 25 16 11 08 07 17 9a 74 1f 00 00 01 28 27 00 00 0a a2 6f 26 00 00 0a 74 03 00 00 1b 13 0d 11 0b } //00 00 
	condition:
		any of ($a_*)
 
}