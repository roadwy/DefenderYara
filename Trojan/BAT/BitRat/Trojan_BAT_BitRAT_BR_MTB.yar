
rule Trojan_BAT_BitRAT_BR_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 6a 01 00 0a 72 90 01 04 6f 6b 01 00 0a 6f 6c 01 00 0a 0d 06 09 6f 6d 90 00 } //01 00 
		$a_03_1 = {28 6f 01 00 0a 13 04 28 6a 01 00 0a 06 6f 70 01 00 0a 11 90 01 01 16 11 90 01 01 8e 69 6f 71 01 00 0a 6f 72 01 00 0a 0c 02 90 00 } //01 00 
		$a_01_2 = {08 28 6f 01 00 0a 28 76 01 00 0a 13 } //00 00 
	condition:
		any of ($a_*)
 
}