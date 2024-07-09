
rule Trojan_BAT_FormBook_AIAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 0d 16 13 04 2b 22 09 11 04 6f ?? 00 00 0a 13 05 07 08 11 05 06 08 06 8e 69 5d 91 59 d1 9d 08 17 58 0c 11 04 17 58 13 04 11 04 09 6f ?? 00 00 0a 32 d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}