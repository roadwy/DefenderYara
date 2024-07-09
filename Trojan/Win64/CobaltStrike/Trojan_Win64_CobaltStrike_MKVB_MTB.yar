
rule Trojan_Win64_CobaltStrike_MKVB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f0 41 c0 e6 ?? 8b c8 c1 e9 ?? 41 32 ce 80 e1 ?? 41 32 ce 48 8b 55 ?? 4c 8b 45 ?? 49 3b d0 73 ?? 48 8d 42 ?? 48 89 45 ?? 48 8d 45 ?? 49 83 f8 ?? 48 0f 43 45 ?? 88 0c 10 c6 44 10 01 ?? eb ?? 44 0f b6 c9 48 8d 4d ?? e8 ?? ?? ?? ?? 4d 3b fc 0f 83 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}