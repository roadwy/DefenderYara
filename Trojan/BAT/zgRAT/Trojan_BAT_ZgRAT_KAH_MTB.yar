
rule Trojan_BAT_ZgRAT_KAH_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 1e 11 09 11 24 11 26 61 11 1b 19 58 61 11 2c 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}