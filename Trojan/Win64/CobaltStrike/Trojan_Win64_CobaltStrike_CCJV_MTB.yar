
rule Trojan_Win64_CobaltStrike_CCJV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 04 24 48 8b 4c 24 ?? 0f b6 04 01 33 44 24 30 48 63 0c 24 48 8b 54 24 ?? 88 04 0a eb } //2
		$a_03_1 = {8b 44 24 4c 83 f0 ?? 8b 4c 24 20 03 c8 8b c1 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}