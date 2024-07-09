
rule Trojan_BAT_Loki_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Loki.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 73 01 00 00 06 28 04 00 00 06 6f ?? 00 00 0a ?? 2d 04 26 26 2b 07 } //5
		$a_03_1 = {07 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 58 0c 08 06 32 e3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}