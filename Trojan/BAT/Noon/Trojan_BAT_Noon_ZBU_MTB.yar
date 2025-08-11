
rule Trojan_BAT_Noon_ZBU_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 12 01 28 ?? 00 00 0a 12 01 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 32 29 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 47 11 06 16 31 42 19 8d ?? 00 00 01 25 16 12 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}