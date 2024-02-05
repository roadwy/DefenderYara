
rule Trojan_BAT_Heracles_PSTA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 14 0c 38 30 00 00 00 00 73 09 00 00 0a 72 8d 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c dd 06 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}