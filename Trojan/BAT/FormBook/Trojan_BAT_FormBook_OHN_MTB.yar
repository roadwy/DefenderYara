
rule Trojan_BAT_FormBook_OHN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.OHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 07 8e 69 5d 91 03 09 91 61 d2 9c 09 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}