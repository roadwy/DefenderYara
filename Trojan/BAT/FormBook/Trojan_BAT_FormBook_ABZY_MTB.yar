
rule Trojan_BAT_FormBook_ABZY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 1f 09 5d 16 fe 01 0d 09 2c 40 02 17 8d 90 01 01 00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 02 18 8d 90 01 01 00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 25 17 11 04 1f 09 61 8c 90 01 01 00 00 01 a2 14 28 90 01 01 01 00 0a 07 17 d6 0b 07 08 fe 04 13 05 11 05 2d a7 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}