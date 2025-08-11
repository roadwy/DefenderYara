
rule Trojan_BAT_FormBook_ATB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ATB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 1e 08 6f ?? 00 00 0a 0d 00 00 03 09 16 6a 28 ?? 00 00 06 58 10 01 00 de 05 26 00 00 de 00 00 08 6f ?? 00 00 0a 2d da de 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}