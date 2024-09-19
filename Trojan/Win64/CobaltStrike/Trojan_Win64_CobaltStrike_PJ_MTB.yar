
rule Trojan_Win64_CobaltStrike_PJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 c1 f9 ?? 29 ca 6b ca ?? 29 c8 89 c2 89 d0 83 c0 ?? 44 89 c1 31 c1 48 8b 55 ?? 8b 45 ?? 48 98 88 0c 02 83 45 ?? ?? 83 7d ?? ?? 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}