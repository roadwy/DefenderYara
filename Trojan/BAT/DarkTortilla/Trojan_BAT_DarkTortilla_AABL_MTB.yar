
rule Trojan_BAT_DarkTortilla_AABL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 1d 5d 16 fe 01 0d 09 2c 42 02 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 10 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 00 00 00 07 17 d6 0b 00 07 08 fe 04 13 05 11 05 2d a4 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}