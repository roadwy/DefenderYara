
rule Trojan_BAT_Lethic_GN_MTB{
	meta:
		description = "Trojan:BAT/Lethic.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {09 07 08 9e 11 04 11 07 d4 7e 90 01 03 04 11 07 d4 91 09 09 06 95 09 07 95 58 20 90 01 03 00 5f 95 61 28 90 01 03 0a 9c 00 11 07 17 6a 58 13 07 11 07 11 04 8e 69 17 59 6a fe 02 16 fe 01 13 08 11 08 2d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}