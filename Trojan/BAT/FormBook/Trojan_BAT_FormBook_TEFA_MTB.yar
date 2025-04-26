
rule Trojan_BAT_FormBook_TEFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.TEFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 04 00 fe 0c 0e 00 fe 0c 04 00 fe 0c 0e 00 91 fe 0c 0e 00 61 d2 9c 00 fe 0c 0e 00 20 01 00 00 00 58 fe 0e 0e 00 fe 0c 0e 00 fe 0c 04 00 8e 69 fe 04 fe 0e 0f 00 fe 0c 0f 00 3a bf ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}