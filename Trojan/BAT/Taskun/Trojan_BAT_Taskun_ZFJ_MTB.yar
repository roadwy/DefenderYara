
rule Trojan_BAT_Taskun_ZFJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 08 11 08 28 ?? 00 00 06 13 09 11 08 28 ?? 00 00 06 13 0a 11 08 28 ?? 00 00 06 13 0b 11 09 11 04 28 ?? 00 00 06 13 09 11 0a 11 04 17 58 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}