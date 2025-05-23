
rule Virus_Win64_Expiro_HNV_MTB{
	meta:
		description = "Virus:Win64/Expiro.HNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 40 00 00 00 ba 00 90 09 ff 00 [0-f0] [0-30] 65 ?? 8b [0-02] 43 90 05 01 03 50 2d 57 4d 8b ?? 10 49 ?? ?? 18 [0-09] 83 ?? 10 ?? 8b ?? ?? ?? ?? 8b ?? 30 ?? 83 ?? 00 74 ?? ?? 8b ?? 60 ?? 8b [0-02] 81 ?? df 00 df 00 ?? 8b ?? 0b [0-06] c1 [0-03] 81 [0-06] 83 ?? 00 74 ?? ?? 8b [0-08] 8b [0-05] 3c [0-05] 83 ?? 10 [0-05] 8b ?? 78 [0-06] 8b ?? 20 ?? 01 ?? ?? 8b ?? ?? ?? ?? 45 8b ?? 0b } //1
		$a_03_1 = {b8 40 00 00 00 ba 00 90 09 ff 00 [0-f0] 81 [0-08] 83 ?? 00 75 [0-10] eb ?? ?? 8b ?? 20 ?? 2b [0-06] c1 ?? 01 ?? 8b ?? 24 ?? 01 [0-08] 8b [0-08] 8b ?? 1c [0-09] c1 [0-15] 8b [0-40] 90 05 01 03 b8 2d bf 40 00 00 00 ba 00 ?? 0b 00 [0-20] 5e 45 [0-20] 0f af ?? ?? ?? ?? ?? 00 [0-50] e8 ?? 00 00 00 [0-09] 8b [0-03] 90 05 03 08 81 f0 2d ff 35 40 2d 4f [0-05] ff } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*3) >=4
 
}