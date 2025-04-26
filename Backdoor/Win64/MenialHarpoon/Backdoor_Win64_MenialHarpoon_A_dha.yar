
rule Backdoor_Win64_MenialHarpoon_A_dha{
	meta:
		description = "Backdoor:Win64/MenialHarpoon.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {89 f1 31 d2 41 b8 0a 00 00 00 e8 90 01 04 04 0a 48 8b 4d 90 01 01 89 c2 e8 90 01 04 48 89 f1 e8 90 01 04 83 c7 03 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}