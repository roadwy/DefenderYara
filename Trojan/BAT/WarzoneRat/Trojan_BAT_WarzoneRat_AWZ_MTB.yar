
rule Trojan_BAT_WarzoneRat_AWZ_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.AWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 0b 2b 23 00 08 17 5f 13 04 08 17 64 0c 11 04 16 fe 03 13 05 11 05 2c 08 08 20 01 a0 00 00 61 0c 00 07 17 58 d2 0b 07 1e fe 02 16 fe 01 13 06 11 06 2d d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}