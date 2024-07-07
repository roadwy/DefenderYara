
rule Trojan_Win64_Tasker_CI_MTB{
	meta:
		description = "Trojan:Win64/Tasker.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 eb 02 38 64 44 8b 5e 04 eb 90 01 02 41 b8 90 01 04 eb 90 01 03 41 bc 90 01 04 eb 90 01 03 4c 8b 36 eb 90 01 02 41 81 f4 90 01 04 71 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}