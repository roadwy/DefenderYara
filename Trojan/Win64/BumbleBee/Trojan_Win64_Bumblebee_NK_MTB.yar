
rule Trojan_Win64_Bumblebee_NK_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 44 8d ?? 32 04 cd ?? ?? ?? ?? 0f b6 c8 41 ?? ?? ?? ?? 0f af c1 41 ?? ?? ?? 8b 05 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 83 c0 ?? 48 63 c8 41 ?? ?? ?? ?? 66 89 04 4b 8b 05 ?? ?? ?? ?? 44 3b c8 7c ?? 4c 8b 05 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}