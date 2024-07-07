
rule Trojan_BAT_Taskun_AAFX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AAFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 34 00 09 11 04 11 08 58 17 58 17 59 11 07 11 09 58 17 58 17 59 6f 90 01 01 00 00 0a 13 0a 12 0a 28 90 01 01 00 00 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d c1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}