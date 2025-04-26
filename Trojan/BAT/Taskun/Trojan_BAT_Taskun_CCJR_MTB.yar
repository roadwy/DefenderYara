
rule Trojan_BAT_Taskun_CCJR_MTB{
	meta:
		description = "Trojan:BAT/Taskun.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a [0-01] 06 28 02 00 00 2b [0-01] 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}