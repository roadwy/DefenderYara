
rule Trojan_Win64_CobaltStrike_AA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 8b c5 ff c5 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 [0-02] 42 0f b6 8c 39 ?? ?? ?? ?? 41 32 4c 00 ff 41 88 4c 18 ff 3b 6c 24 ?? 72 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}