
rule Trojan_Win64_CobaltStrike_IG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c3 39 f7 7e ?? 48 89 f0 83 e0 ?? 45 8a 2c 04 44 32 6c 35 ?? ff 15 ?? ?? ?? ?? 44 88 2c 33 48 ff c6 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}