
rule Trojan_BAT_FormBook_MBWC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 61 62 41 67 72 65 65 38 65 6e 74 2e 65 78 65 00 6d 6f 61 62 32 79 65 00 6d 6f 61 62 37 79 65 00 6d 6f 61 62 41 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}