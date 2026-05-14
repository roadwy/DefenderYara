
rule Trojan_BAT_FormBook_ZQI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ZQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5a 59 7e ?? 00 00 04 1f 09 7e ?? 00 00 04 1f 09 93 04 61 1f 75 5f 9d 30 12 11 05 1f 57 91 20 c0 00 00 00 59 13 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}