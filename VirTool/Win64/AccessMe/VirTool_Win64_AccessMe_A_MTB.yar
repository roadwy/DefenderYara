
rule VirTool_Win64_AccessMe_A_MTB{
	meta:
		description = "VirTool:Win64/AccessMe.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {ff d0 89 85 90 01 03 00 b9 e8 03 00 00 48 8b 05 90 01 03 00 ff d0 48 8b 05 90 01 03 00 ff d0 90 00 } //02 00 
		$a_02_1 = {48 8d 70 01 48 89 f1 e8 90 01 02 00 00 49 89 f0 48 89 44 dd 00 48 8b 14 df 48 89 c1 e8 90 01 02 00 00 90 00 } //02 00 
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 2e 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}