
rule Trojan_BAT_FormBook_EUQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 1f 16 d6 1f 0b da 1f 0b da 02 11 06 1f 16 d6 1f 0b da 1f 0b da 91 08 61 07 ?? ?? ?? ?? ?? 11 07 91 61 b4 9c 1f 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}