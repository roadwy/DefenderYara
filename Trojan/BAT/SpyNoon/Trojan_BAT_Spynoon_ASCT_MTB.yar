
rule Trojan_BAT_Spynoon_ASCT_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 00 0d 2b 34 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 09 16 fe 04 16 fe 01 13 06 11 06 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}