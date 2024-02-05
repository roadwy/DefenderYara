
rule Trojan_BAT_Nanocore_FEGA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.FEGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {19 8d 13 00 00 01 13 09 11 09 16 02 a2 11 09 17 16 8c 05 00 00 01 a2 11 09 18 02 8e b7 8c 05 00 00 01 a2 11 09 13 0a 11 0a 14 14 19 8d 01 00 00 01 13 0b 11 0b 16 17 9c 11 0b 17 16 9c 11 0b 18 16 9c 11 0b 17 } //00 00 
	condition:
		any of ($a_*)
 
}