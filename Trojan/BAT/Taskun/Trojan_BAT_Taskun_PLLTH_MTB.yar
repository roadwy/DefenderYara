
rule Trojan_BAT_Taskun_PLLTH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PLLTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 1f 10 62 0f 01 28 ?? 01 00 0a 1e 62 60 0f 01 28 ?? 01 00 0a 60 0b 02 19 8d ?? 00 00 01 25 16 07 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 07 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 07 20 ?? 00 00 00 5f d2 9c 6f ?? 01 00 0a 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}