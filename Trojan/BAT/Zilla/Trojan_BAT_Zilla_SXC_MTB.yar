
rule Trojan_BAT_Zilla_SXC_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 72 ?? ?? 00 70 11 06 73 0d 00 00 0a 13 07 11 07 16 6f ?? 00 00 0a 00 11 07 17 } //30
		$a_03_1 = {1f 1a 58 1f 1a 5d 1f 61 58 d1 13 04 08 11 04 6f ?? 00 00 0a 26 00 2b 1d } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}