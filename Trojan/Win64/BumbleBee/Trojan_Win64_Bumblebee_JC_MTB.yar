
rule Trojan_Win64_Bumblebee_JC_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.JC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c1 89 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 43 ?? 8b 8b ?? ?? ?? ?? 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}