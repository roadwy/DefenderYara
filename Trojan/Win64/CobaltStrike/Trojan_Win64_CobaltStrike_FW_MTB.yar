
rule Trojan_Win64_CobaltStrike_FW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 2b 83 ?? ?? ?? ?? 89 4b ?? 83 f0 ?? 41 0f af c1 89 43 ?? 8b 4b ?? 2b ca 81 c1 ?? ?? ?? ?? 31 4b ?? 49 81 fb ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}