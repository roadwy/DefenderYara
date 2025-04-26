
rule Trojan_BAT_Heracles_EAHO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {1a 8d 08 00 00 01 0a 02 06 16 1a 6f 06 00 00 0a 26 06 16 28 09 00 00 0a 0b 07 8d 08 00 00 01 0c 16 0d 2b 0e 09 02 08 09 07 09 59 6f 06 00 00 0a 58 0d 09 07 32 ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}