
rule Trojan_BAT_Redcap_NN_MTB{
	meta:
		description = "Trojan:BAT/Redcap.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 0b 61 20 95 ?? ?? ?? 07 61 0b 0a ?? ?? ?? ?? ?? 07 5a 0b 02 07 ?? ?? ?? ?? ?? 61 0b 02 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Redcap_NN_MTB_2{
	meta:
		description = "Trojan:BAT/Redcap.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 64 0a 07 06 59 1f 1f 64 13 04 07 06 11 04 17 59 5f 59 0b 08 17 62 17 11 04 59 60 0c 06 20 00 ?? ?? ?? 41 15 ?? ?? ?? 07 1e 62 02 7b 62 01 ?? ?? 6f 0f 02 ?? ?? d2 60 0b 06 1e 62 0a 09 17 59 0d 09 16 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}