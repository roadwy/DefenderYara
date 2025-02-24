
rule Trojan_BAT_Stealer_PAFN_MTB{
	meta:
		description = "Trojan:BAT/Stealer.PAFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 d1 13 12 11 ?? 11 ?? 91 13 ?? 11 ?? 11 ?? 11 ?? 11 ?? 61 11 1e 19 58 61 11 32 61 d2 9c 17 11 0a 58 13 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}