
rule Trojan_BAT_Injuke_AWGA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AWGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 08 7e 08 00 00 04 11 08 91 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 11 08 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 8e 69 5d 91 61 d2 9c 00 11 08 17 58 13 08 11 08 7e 08 00 00 04 8e 69 fe 04 13 09 11 09 2d b5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}