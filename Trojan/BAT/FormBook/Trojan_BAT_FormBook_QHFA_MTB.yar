
rule Trojan_BAT_FormBook_QHFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.QHFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 16 08 02 00 0b 2b 13 00 06 07 20 00 01 00 00 28 ?? ?? ?? 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d e2 } //1
		$a_01_1 = {43 00 49 00 53 00 2e 00 42 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00 46 00 61 00 63 00 61 00 64 00 65 00 } //1 CIS.BusinessFacade
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}