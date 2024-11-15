
rule Trojan_BAT_RedlineStealer_AMH_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.AMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {6e 5b 26 11 ?? 6e 11 ?? 6a 5b 26 11 } //1
		$a_03_1 = {0a 26 16 13 ?? 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 13 ?? 03 11 ?? 91 13 ?? 06 11 ?? 91 13 ?? 11 ?? 11 ?? 61 d2 13 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}