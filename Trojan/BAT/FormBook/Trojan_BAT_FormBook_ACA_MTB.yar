
rule Trojan_BAT_FormBook_ACA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0d 2b 23 00 07 09 18 6f c4 00 00 0a 20 03 02 00 00 28 c5 00 00 0a 13 05 08 11 05 6f c6 00 00 0a 00 09 18 58 0d 00 09 07 6f c7 00 00 0a fe 04 13 06 11 06 2d ce } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}