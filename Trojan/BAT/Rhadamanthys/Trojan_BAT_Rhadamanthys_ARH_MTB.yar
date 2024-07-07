
rule Trojan_BAT_Rhadamanthys_ARH_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 1b 2d 03 26 2b 66 0a 2b fb 00 72 01 00 00 70 28 90 01 03 06 73 02 00 00 0a 16 2c 03 26 2b 03 0b 2b 00 73 03 00 00 0a 1b 2d 03 26 2b 03 0c 2b 00 07 16 73 04 00 00 0a 73 05 00 00 0a 0d 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}