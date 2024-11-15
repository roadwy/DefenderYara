
rule Backdoor_Win64_MenialHarpoon_B_dha{
	meta:
		description = "Backdoor:Win64/MenialHarpoon.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 20 41 b8 0a 00 00 00 48 8d 54 24 ?? 48 8b cb ff 15 ?? ?? ?? ?? 44 8b c8 48 3b 5c 24 ?? 0f 84 ?? ?? ?? ?? 41 83 3e 22 0f 84 ?? ?? ?? ?? 41 80 c1 0a 48 8b 4f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}