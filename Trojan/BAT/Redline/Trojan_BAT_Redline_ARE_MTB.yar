
rule Trojan_BAT_Redline_ARE_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e 2c f4 2b 37 00 2b 17 2b 18 2b 1d 9a 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a 2c 02 de 24 de 10 06 2b e6 6f ?? ?? ?? 0a 2b e1 07 2b e0 26 de 00 1b 2c d3 16 2d c2 07 16 2d 02 17 58 0b 07 1f 0a 32 c4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Redline_ARE_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 09 2b 70 11 08 11 09 9a 0d 7e 2e 00 00 0a 13 04 09 6f 2f 00 00 0a 13 05 11 05 6f 30 00 00 0a 13 06 16 13 07 2b 38 11 04 11 06 11 07 8f 2d 00 00 01 28 31 00 00 0a 28 32 00 00 0a 13 04 11 07 11 06 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}