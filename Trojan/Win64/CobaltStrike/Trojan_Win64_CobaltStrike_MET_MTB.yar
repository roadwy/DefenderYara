
rule Trojan_Win64_CobaltStrike_MET_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 04 11 48 83 c2 ?? 8b 8b ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 03 c1 35 ?? ?? ?? ?? 29 43 ?? 8b 43 ?? 83 e8 ?? 01 43 ?? 8b 83 ?? ?? ?? ?? 33 c1 35 ?? ?? ?? ?? 29 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 29 43 ?? 48 81 fa ?? ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}