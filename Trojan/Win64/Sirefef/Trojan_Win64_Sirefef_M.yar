
rule Trojan_Win64_Sirefef_M{
	meta:
		description = "Trojan:Win64/Sirefef.M,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0b 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 81 f8 64 69 73 63 } //02 00 
		$a_00_1 = {41 81 f8 63 6e 63 74 } //02 00 
		$a_00_2 = {41 81 f8 73 65 6e 64 } //02 00 
		$a_00_3 = {41 81 f8 72 65 63 76 } //01 00 
		$a_00_4 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 } //01 00  Content-Length: 
		$a_00_5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 } //02 00  User-Agent: 
		$a_00_6 = {ba 72 65 63 76 } //02 00 
		$a_00_7 = {ba 63 6e 63 74 } //06 00 
		$a_00_8 = {63 6e 71 61 7a 77 73 78 65 64 63 72 66 76 74 67 65 61 62 79 68 6e 75 6a 6d 69 6b 6f 69 6a 6c 70 } //02 00  cnqazwsxedcrfvtgeabyhnujmikoijlp
		$a_03_9 = {61 73 6b 3f 61 3d 90 02 04 26 75 3d 25 75 26 6d 3d 25 78 26 68 3d 25 78 90 00 } //02 00 
		$a_00_10 = {49 6f 70 46 61 69 6c 5a 65 72 6f 41 63 63 65 73 73 43 72 65 61 74 65 } //00 00  IopFailZeroAccessCreate
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Sirefef_M_2{
	meta:
		description = "Trojan:Win64/Sirefef.M,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 08 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 81 f8 64 69 73 63 } //02 00 
		$a_01_1 = {41 81 f8 63 6e 63 74 } //02 00 
		$a_01_2 = {41 81 f8 73 65 6e 64 } //02 00 
		$a_01_3 = {41 81 f8 72 65 63 76 } //02 00 
		$a_01_4 = {ba 72 65 63 76 } //02 00 
		$a_01_5 = {ba 63 6e 63 74 } //02 00 
		$a_01_6 = {ba 64 69 73 63 } //06 00 
		$a_00_7 = {63 6e 71 61 7a 77 73 78 65 64 63 72 66 76 74 67 65 61 62 79 68 6e 75 6a 6d 69 6b 6f 69 6a 6c 70 } //02 00  cnqazwsxedcrfvtgeabyhnujmikoijlp
		$a_03_8 = {61 73 6b 3f 61 3d 90 02 04 26 75 3d 25 75 26 6d 3d 25 78 26 68 3d 25 78 90 00 } //02 00 
		$a_00_9 = {49 6f 70 46 61 69 6c 5a 65 72 6f 41 63 63 65 73 73 43 72 65 61 74 65 } //00 00  IopFailZeroAccessCreate
	condition:
		any of ($a_*)
 
}