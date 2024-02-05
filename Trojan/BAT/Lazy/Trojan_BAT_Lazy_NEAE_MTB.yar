
rule Trojan_BAT_Lazy_NEAE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 fe 0c 00 00 7e 01 00 00 04 6f 06 00 00 0a 00 fe 0c 00 00 7e 02 00 00 04 6f 07 00 00 0a 00 fe 0c 00 00 20 01 00 00 00 6f 08 00 00 0a 00 fe 0c 00 00 20 02 00 00 00 6f 09 00 00 0a 00 fe 0c 00 00 fe 0c 00 00 6f 0a 00 00 0a fe 0c 00 00 6f 0b 00 00 0a 6f 0c 00 00 0a fe 0e 01 00 7e 04 00 00 04 73 0d 00 00 0a fe 0e 02 00 } //05 00 
		$a_01_1 = {47 00 74 00 4c 00 41 00 4f 00 55 00 37 00 72 00 61 00 6b 00 59 00 42 00 42 00 47 00 65 00 42 00 39 00 77 00 4e 00 4b 00 69 00 51 00 3d 00 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}