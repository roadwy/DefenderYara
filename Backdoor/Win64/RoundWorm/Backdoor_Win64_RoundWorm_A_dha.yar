
rule Backdoor_Win64_RoundWorm_A_dha{
	meta:
		description = "Backdoor:Win64/RoundWorm.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {c5 03 48 63 cd 48 8b 46 90 01 01 48 3b c8 0f 82 90 01 04 48 8b 56 90 01 01 48 83 fa 0f 76 2c 48 ff c2 48 8b 0e 48 81 fa 00 10 00 00 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}