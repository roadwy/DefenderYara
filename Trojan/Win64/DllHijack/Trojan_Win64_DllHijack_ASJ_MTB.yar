
rule Trojan_Win64_DllHijack_ASJ_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 0f b6 44 04 ?? 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}