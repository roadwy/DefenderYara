
rule Trojan_BAT_Lazy_ASVN_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ASVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 1f 10 0c 03 07 06 28 90 01 03 06 0d 03 07 06 58 03 8e 69 06 59 07 59 08 59 28 90 00 } //01 00 
		$a_01_1 = {43 00 68 00 6c 00 6f 00 6e 00 69 00 75 00 6d 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}