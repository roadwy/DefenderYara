
rule Trojan_BAT_FormBook_ELFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ELFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 f8 00 00 0b 2b 16 06 07 20 00 01 00 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0a 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d df } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}