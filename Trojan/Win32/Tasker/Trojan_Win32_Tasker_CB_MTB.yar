
rule Trojan_Win32_Tasker_CB_MTB{
	meta:
		description = "Trojan:Win32/Tasker.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {ff 34 1a bf 80 d6 b3 38 59 66 8b c2 81 f1 ee 6a 67 66 bf 62 a5 a1 10 81 f1 8f 3b b1 3e 81 c1 1c 1e 36 11 be 6b d1 f4 3f 89 0c 13 66 b8 9d 2a 83 ea 04 66 bf 6a 0a 81 fa ac f5 ff ff 0f 85 } //01 00 
		$a_00_1 = {66 8b c6 e9 } //02 00 
		$a_81_2 = {61 74 6f 6d 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}