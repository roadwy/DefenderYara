
rule Trojan_Win64_CobaltStrike_QM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 b8 ?? ?? ?? ?? ff 43 ?? 8b 8b ?? ?? ?? ?? 33 8b ?? ?? ?? ?? 2b c1 01 05 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 43 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}