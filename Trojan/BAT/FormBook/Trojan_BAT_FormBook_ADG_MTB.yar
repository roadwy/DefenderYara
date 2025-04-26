
rule Trojan_BAT_FormBook_ADG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 0a 07 11 0a 91 13 0b 11 0b 11 07 61 11 09 59 20 00 02 00 00 58 13 0c 02 11 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}