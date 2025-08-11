
rule Trojan_BAT_FormBook_TRT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.TRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0d 11 0d 06 7d 47 03 00 04 00 11 0d 02 11 0a 11 0c 6f ?? 00 00 0a 7d 45 03 00 04 11 0d 04 11 0d 7b 47 03 00 04 7b 44 03 00 04 6f ?? 00 00 0a 59 7d 46 03 00 04 7e 49 03 00 04 25 2d 17 26 7e 48 03 00 04 fe 06 82 02 00 06 73 86 00 00 0a 25 80 49 03 00 04 13 0e 11 0d fe 06 7e 02 00 06 73 86 00 00 0a 13 0f 11 0d fe 06 7f 02 00 06 73 86 00 00 0a 13 10 11 0d 7b 46 03 00 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}