
rule Trojan_BAT_ClipBanker_EAAJ_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.EAAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 02 6f 1b 00 00 0a 07 59 6f 1c 00 00 0a 03 03 6f 1b 00 00 0a 07 59 6f 1c 00 00 0a fe 01 16 fe 01 0c 08 2c 03 00 2b 24 06 17 58 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}