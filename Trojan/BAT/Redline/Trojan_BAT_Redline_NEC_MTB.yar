
rule Trojan_BAT_Redline_NEC_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 00 12 03 12 04 08 12 05 12 06 12 07 12 08 02 7e 07 00 00 04 06 97 29 1c 00 00 11 13 09 00 de 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}