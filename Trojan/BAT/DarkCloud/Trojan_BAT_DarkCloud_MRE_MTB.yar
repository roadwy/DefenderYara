
rule Trojan_BAT_DarkCloud_MRE_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.MRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 02 7b 06 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 2d 00 00 0a 13 04 11 04 09 17 73 2e 00 00 0a 13 05 2b 32 2b 34 16 2b 34 8e 69 2b 33 2b 38 2b 3a 2b 3f 2b 41 2b 46 11 06 03 72 3e 02 00 70 28 ?? 00 00 06 05 72 62 02 00 70 6f ?? 00 00 0a 17 0b dd 80 00 00 00 11 05 2b ca 06 2b c9 06 2b c9 6f ?? 00 00 0a 2b c6 11 05 2b c4 6f ?? 00 00 0a 2b bf 11 04 2b bd 6f ?? 00 00 0a 2b b8 13 06 2b b6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}