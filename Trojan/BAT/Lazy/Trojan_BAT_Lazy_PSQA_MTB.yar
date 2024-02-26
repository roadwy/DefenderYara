
rule Trojan_BAT_Lazy_PSQA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 6f 7d 00 00 0a 0c 07 08 17 73 90 01 03 0a 0d 02 28 28 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f 90 01 03 0a 09 6f 90 01 03 0a 07 6f 90 01 03 0a 13 05 28 90 01 03 0a 11 05 16 11 05 8e 69 6f 90 01 03 0a 13 06 de 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}