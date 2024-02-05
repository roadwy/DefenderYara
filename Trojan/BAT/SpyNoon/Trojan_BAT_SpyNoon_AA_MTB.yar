
rule Trojan_BAT_SpyNoon_AA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 07 58 20 ff 00 00 00 5f 61 d2 9c 08 17 58 0c 08 06 8e 69 17 59 } //00 00 
	condition:
		any of ($a_*)
 
}