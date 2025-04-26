
rule Trojan_BAT_AsyncRAT_PHX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 6f ?? 00 00 0a 28 ?? 00 00 06 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 58 7e ?? 00 00 04 58 7e ?? 00 00 04 58 5a 1f 1f 5f 62 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 7e ?? 00 00 04 58 6f ?? 00 00 0a 28 ?? 00 00 06 58 d2 9c 11 04 17 58 13 04 11 04 06 7e ?? 00 00 04 1f 1f 5f 63 32 93 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}