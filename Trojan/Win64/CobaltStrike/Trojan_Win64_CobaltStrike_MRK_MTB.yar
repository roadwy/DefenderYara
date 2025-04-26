
rule Trojan_Win64_CobaltStrike_MRK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 49 8b c1 49 f7 f0 4c 8b c2 33 d2 49 8b c1 48 f7 f1 42 0f b6 44 1a ?? 43 0f b6 8c 18 ?? ?? ?? 00 0f af c8 41 02 ca 41 30 0c 39 41 ff c2 45 3b 13 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}