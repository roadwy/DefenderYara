
rule Trojan_BAT_AsyncRAT_AW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 11 07 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 26 20 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}