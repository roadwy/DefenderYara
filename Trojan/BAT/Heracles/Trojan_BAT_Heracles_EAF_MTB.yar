
rule Trojan_BAT_Heracles_EAF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b 26 16 0d 2b 21 0a 2b e3 0b 2b ea 0c 2b f3 08 09 18 5b 06 09 18 6f 90 01 01 01 00 0a 1f 10 28 90 01 01 01 00 0a 9c 09 18 58 0d 09 07 32 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}