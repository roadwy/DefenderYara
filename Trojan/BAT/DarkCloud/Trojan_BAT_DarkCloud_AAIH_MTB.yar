
rule Trojan_BAT_DarkCloud_AAIH_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AAIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 06 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d ac } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}