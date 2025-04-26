
rule Trojan_Win64_CobaltStrike_QF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 } //1
		$a_03_1 = {8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}