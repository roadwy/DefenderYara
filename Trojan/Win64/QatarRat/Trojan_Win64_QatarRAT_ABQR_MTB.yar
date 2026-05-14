
rule Trojan_Win64_QatarRAT_ABQR_MTB{
	meta:
		description = "Trojan:Win64/QatarRAT.ABQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 83 f8 ?? ?? ?? 48 63 04 24 48 8b 4c 24 ?? 0f be 04 01 8b 0c 24 83 e9 ?? 0f be c9 33 c1 48 63 0c 24 48 8b 54 24 ?? 88 04 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}