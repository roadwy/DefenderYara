
rule Trojan_BAT_FormBook_STG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.STG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}