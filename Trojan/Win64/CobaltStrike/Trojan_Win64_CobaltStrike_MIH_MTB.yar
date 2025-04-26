
rule Trojan_Win64_CobaltStrike_MIH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 03 d1 48 8b ca 8b 14 24 c1 ea ?? 81 e2 ff 00 00 00 8b d2 33 04 91 b9 00 04 00 00 48 6b c9 ?? 48 8d 15 15 69 01 00 48 03 d1 48 8b ca 8b 14 24 c1 ea 18 8b d2 33 04 91 89 04 24 48 8b 44 24 30 48 83 e8 04 48 89 44 24 30 e9 25 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}