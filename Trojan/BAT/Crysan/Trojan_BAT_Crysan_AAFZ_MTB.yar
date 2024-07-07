
rule Trojan_BAT_Crysan_AAFZ_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 fe 0e 03 00 20 fc ff ff ff 20 ba 8e fa fb 20 54 0e d4 88 61 20 ee 80 2e 73 40 90 01 01 00 00 00 20 02 00 00 00 fe 0e 03 00 fe 90 01 02 00 00 01 58 00 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}