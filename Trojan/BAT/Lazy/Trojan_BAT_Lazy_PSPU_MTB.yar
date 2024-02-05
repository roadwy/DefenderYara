
rule Trojan_BAT_Lazy_PSPU_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 06 73 7a 00 00 0a 0c 16 13 0a 2b 2a 00 08 11 09 11 0a 8f 14 00 00 02 7c 2c 00 00 04 7b 22 00 00 04 28 7b 00 00 0a 6f 7c 00 00 0a de 03 } //00 00 
	condition:
		any of ($a_*)
 
}