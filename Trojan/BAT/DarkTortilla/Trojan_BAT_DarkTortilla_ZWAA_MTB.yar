
rule Trojan_BAT_DarkTortilla_ZWAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 14 72 85 34 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 11 04 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 0a 11 09 12 0a 28 ?? 01 00 0a 13 0c 11 0c 2d c4 11 04 6f ?? 01 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0a 2b 00 06 2a } //3
		$a_03_1 = {0a 0c 08 14 72 63 34 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 13 07 11 07 2c 1d 08 14 72 6b 34 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0d } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}