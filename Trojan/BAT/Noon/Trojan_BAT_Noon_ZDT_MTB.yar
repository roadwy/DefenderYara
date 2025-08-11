
rule Trojan_BAT_Noon_ZDT_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 1e 11 1f 6f ?? 00 00 0a 13 22 12 22 28 ?? 00 00 0a 16 61 d2 13 23 12 22 28 ?? 00 00 0a 16 61 d2 13 24 12 22 28 ?? 00 00 0a 16 61 d2 13 25 19 8d ?? 00 00 01 13 26 11 26 16 11 23 6c 23 00 00 00 00 00 e0 6f 40 5b a1 11 26 17 11 24 6c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}