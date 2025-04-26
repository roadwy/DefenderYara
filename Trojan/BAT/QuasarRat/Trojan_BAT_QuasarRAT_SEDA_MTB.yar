
rule Trojan_BAT_QuasarRAT_SEDA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.SEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a } //3
		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0b 0e 04 05 6f ?? 00 00 0a 59 0c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}