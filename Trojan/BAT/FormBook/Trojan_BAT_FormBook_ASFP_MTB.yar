
rule Trojan_BAT_FormBook_ASFP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ASFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 ?? 00 00 0a 9c 09 03 8e 69 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 17 59 31 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}