
rule Trojan_BAT_Heracles_SEDA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 01 00 0a 11 } //3
		$a_03_1 = {58 12 02 28 ?? 00 00 0a 58 20 88 13 00 00 5d 20 e8 03 00 00 58 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_BAT_Heracles_SEDA_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 } //3
		$a_03_1 = {09 1b 5a 11 08 19 5a 58 20 f4 01 00 00 5d 20 c8 00 00 00 58 13 09 11 08 1f 1e 5d 1f 0a 58 13 0a 09 1f 28 5d 1b 58 13 0b 02 09 11 08 6f ?? 00 00 0a 13 0c } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}