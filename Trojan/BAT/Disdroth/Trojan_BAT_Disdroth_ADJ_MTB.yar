
rule Trojan_BAT_Disdroth_ADJ_MTB{
	meta:
		description = "Trojan:BAT/Disdroth.ADJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 0a 17 0b 0e 04 2c 13 0e 04 17 33 1a 7e 5c 00 00 0a 02 6f 61 00 00 0a 0a 2b 0c 7e 5e 00 00 0a 02 6f 61 00 00 0a 0a 06 2c 09 06 03 04 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}