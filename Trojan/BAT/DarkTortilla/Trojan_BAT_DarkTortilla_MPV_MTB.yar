
rule Trojan_BAT_DarkTortilla_MPV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 74 3a 00 00 01 08 74 02 01 00 01 1f 20 6f ?? 03 00 0a 6f ?? 03 00 0a 09 75 3a 00 00 01 08 74 02 01 00 01 1f 10 6f 55 03 00 0a 6f 19 03 00 0a 19 13 0c 2b a8 09 75 3a 00 00 01 09 75 3a 00 00 01 6f ?? 03 00 0a 09 74 3a 00 00 01 6f ?? 03 00 0a 6f ?? 03 00 0a 13 04 16 13 0c 2b 80 } //5
		$a_03_1 = {11 07 75 03 01 00 01 02 16 02 8e 69 6f ?? 03 00 0a 11 07 74 03 01 00 01 6f ?? 03 00 0a 1b 13 10 2b bf } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}