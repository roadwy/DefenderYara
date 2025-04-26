
rule Trojan_Win64_CobaltStrike_BI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b 04 24 48 03 44 24 ?? 48 03 44 24 ?? 0f b6 04 28 30 04 0b ff c3 48 83 ef ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_BI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 48 63 d0 48 8d 85 70 ff ff ff 48 89 c1 e8 [0-04] 0f b6 00 30 45 fb 83 45 f4 01 8b 45 f4 48 63 d8 48 8d 85 70 ff ff ff 48 89 c1 e8 [0-04] 48 39 c3 0f 92 c0 84 c0 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}