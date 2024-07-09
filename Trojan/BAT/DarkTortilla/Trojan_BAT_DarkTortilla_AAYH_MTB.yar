
rule Trojan_BAT_DarkTortilla_AAYH_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 05 74 ?? 00 00 01 11 04 75 ?? 00 00 1b 6f ?? 00 00 0a 16 13 0c 2b b3 11 05 75 ?? 00 00 01 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 } //2
		$a_03_1 = {01 02 16 02 8e 69 6f ?? 00 00 0a 11 08 74 ?? 00 00 01 6f ?? 00 00 0a 19 13 10 2b bf } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}