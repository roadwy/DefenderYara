
rule Trojan_Win64_BumbleBee_HJ_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.HJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 5c 24 ?? 44 8b 88 ?? ?? ?? ?? 44 2b 4b ?? 44 03 8b ?? ?? ?? ?? 44 8b 80 ?? ?? ?? ?? 44 0f af c2 8b 93 ?? ?? ?? ?? 33 93 ?? ?? ?? ?? 44 89 54 24 ?? 81 e2 ?? ?? ?? ?? 44 89 4c 24 ?? 4c 8b cb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}