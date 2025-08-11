
rule Trojan_BAT_Taskun_PGT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 16 11 17 6f ?? 00 00 0a 13 18 11 0a 12 18 28 ?? 00 00 0a 58 13 0a 11 0b 12 18 28 ?? 00 00 0a 58 13 0b 11 0c 12 18 28 ?? 00 00 0a 58 13 0c 12 18 28 ?? 00 00 0a 12 18 28 ?? 00 00 0a 58 12 18 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}