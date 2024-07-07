
rule Trojan_BAT_RedLine_MBDD_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 2d 9d 6f 90 01 01 00 00 0a 0b 07 8e 69 8d 90 01 01 00 00 01 0d 16 0a 2b 12 09 06 07 06 9a 1f 10 28 90 01 01 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 06 11 06 2d e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}