
rule Trojan_BAT_Lazy_PSKB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 07 08 28 87 00 00 0a 7e 0e 00 00 04 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 00 07 18 6f 90 01 03 0a 00 07 6f 90 01 03 0a 13 05 02 13 06 11 05 11 06 16 11 06 8e 69 6f 90 01 03 0a 0a de 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}