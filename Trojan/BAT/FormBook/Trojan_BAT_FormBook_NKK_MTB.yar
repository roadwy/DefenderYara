
rule Trojan_BAT_FormBook_NKK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 6a 61 d2 9c 00 11 10 17 58 13 10 11 10 11 08 17 59 fe 02 16 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}