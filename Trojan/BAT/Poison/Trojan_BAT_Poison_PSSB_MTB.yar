
rule Trojan_BAT_Poison_PSSB_MTB{
	meta:
		description = "Trojan:BAT/Poison.PSSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 6b 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 18 2d 09 26 12 00 1a 2d 06 26 de 0d 0a 2b f5 28 90 01 01 00 00 06 2b f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}