
rule Trojan_Win64_CobaltStrike_HMN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 41 8b c8 2b c8 48 63 d1 48 8b 45 ?? 0f b6 8c 32 ?? ?? ?? ?? 41 32 0c 01 41 88 0c 19 41 ff c0 4d 8d 49 ?? 44 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}