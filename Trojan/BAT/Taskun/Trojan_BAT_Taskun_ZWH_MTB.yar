
rule Trojan_BAT_Taskun_ZWH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 19 8d ?? 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 7d ca 00 00 04 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}