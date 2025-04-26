
rule Trojan_BAT_Taskun_KAC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 09 11 04 11 22 58 11 21 11 23 58 6f ?? ?? 00 0a 13 24 12 24 28 ?? ?? 00 0a 13 25 08 07 11 25 9c 07 17 58 0b 11 23 17 58 13 23 00 11 23 17 fe 04 13 26 11 26 2d c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}