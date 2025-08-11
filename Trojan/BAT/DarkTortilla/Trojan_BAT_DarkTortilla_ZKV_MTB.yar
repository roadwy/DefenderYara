
rule Trojan_BAT_DarkTortilla_ZKV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 13 04 11 04 45 07 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 1b 00 00 00 40 00 00 00 1b 00 00 00 51 00 00 00 28 ?? 01 00 0a 0b 07 74 34 00 00 01 14 fe 03 0c 08 2c 05 19 13 04 2b c5 1c 2b f9 07 74 34 00 00 01 7e 6c 00 00 04 6f 3b 01 00 0a 07 75 34 00 00 01 7e 6c 00 00 04 6f ?? 01 00 0a 1a 13 04 2b 9d } //5
		$a_03_1 = {02 7b 83 00 00 04 6f ?? 01 00 0a 0a 06 75 37 00 00 01 2a } //4
		$a_03_2 = {02 03 16 03 8e 69 6f ?? 01 00 0a 02 6f ?? 01 00 0a 1a 0b 2b d1 } //3
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4+(#a_03_2  & 1)*3) >=12
 
}