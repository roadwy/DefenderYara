
rule Trojan_BAT_DarkTortilla_FZD_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.FZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 14 fe 03 0c 08 2c 7d 07 7e 4b 00 00 04 7e 4d 00 00 04 2c 07 7e 4d 00 00 04 2b 16 7e 4c 00 00 04 fe 06 74 00 00 06 73 ce 00 00 0a 25 80 4d 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 6f d1 00 00 0a 00 07 7e 4b 00 00 04 7e 4e 00 00 04 2c 07 7e 4e 00 00 04 2b 16 } //5
		$a_03_1 = {2b 16 7e 4c 00 00 04 fe 06 75 00 00 06 73 ce 00 00 0a 25 80 4e 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 00 07 19 6f ?? 00 00 0a 00 00 00 07 0a 2b 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}