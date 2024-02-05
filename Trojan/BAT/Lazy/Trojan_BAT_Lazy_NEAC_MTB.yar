
rule Trojan_BAT_Lazy_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 fe 09 08 00 71 02 00 00 1b fe 09 0a 00 71 03 00 00 01 91 61 d2 9c fe 09 0a 00 71 03 00 00 01 20 01 00 00 00 58 fe 0e 00 00 fe 09 0a 00 fe 0c 00 00 81 03 00 00 01 fe 09 0a 00 71 03 00 00 01 fe 09 08 00 71 02 00 00 1b 8e 69 fe 04 } //00 00 
	condition:
		any of ($a_*)
 
}