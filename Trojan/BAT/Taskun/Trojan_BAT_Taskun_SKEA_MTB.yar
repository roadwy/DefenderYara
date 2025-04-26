
rule Trojan_BAT_Taskun_SKEA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SKEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 19 8d df 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a } //3
		$a_03_1 = {0e 04 05 6f ?? 00 00 0a 59 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}