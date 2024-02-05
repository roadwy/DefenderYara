
rule Trojan_BAT_Lazy_PSUE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 03 00 00 06 0b 14 0c 14 0d 0e 04 13 05 11 05 2c 17 00 07 03 72 30 15 00 70 04 28 10 00 00 0a 6f 11 00 00 0a 0d 00 2b 1c } //00 00 
	condition:
		any of ($a_*)
 
}