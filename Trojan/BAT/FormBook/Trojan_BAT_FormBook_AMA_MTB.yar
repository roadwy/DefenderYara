
rule Trojan_BAT_FormBook_AMA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 11 05 91 11 06 61 11 08 28 ?? 01 00 06 13 09 07 11 05 11 09 28 ?? 01 00 06 9c 11 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}