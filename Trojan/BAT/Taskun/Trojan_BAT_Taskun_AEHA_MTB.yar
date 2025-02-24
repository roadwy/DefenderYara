
rule Trojan_BAT_Taskun_AEHA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AEHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 10 12 08 28 ?? 00 00 0a 1f 10 62 12 08 28 ?? 00 00 0a 1e 62 60 12 08 28 ?? 00 00 0a 60 13 11 11 07 11 11 61 13 07 16 13 12 } //3
		$a_03_1 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c 13 18 03 11 18 11 09 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}