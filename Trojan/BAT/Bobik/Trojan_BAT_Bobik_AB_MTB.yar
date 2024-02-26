
rule Trojan_BAT_Bobik_AB_MTB{
	meta:
		description = "Trojan:BAT/Bobik.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 0a 06 2c 17 00 03 04 28 17 00 00 0a 28 29 00 00 0a 6f 2a 00 00 0a 00 17 0b 2b 04 16 0b 2b 00 07 2a } //00 00 
	condition:
		any of ($a_*)
 
}