
rule TrojanDropper_Win32_Percol_B{
	meta:
		description = "TrojanDropper:Win32/Percol.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_90_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 5c 41 41 56 5c 5c 43 44 72 69 76 65 72 2e 73 79 73 } //01 00  C:\Program Files\\AAV\\CDriver.sys
		$a_01_1 = {43 44 72 69 76 65 72 2e 49 6e 66 } //01 00  CDriver.Inf
		$a_01_2 = {2a 43 44 72 69 76 65 72 } //01 00  *CDriver
		$a_00_3 = {c6 85 a4 fd ff ff 50 c6 85 a5 fd ff ff 72 c6 85 a6 fd ff ff 6f c6 85 a7 fd ff ff 67 c6 85 a8 fd ff ff 72 c6 85 a9 fd ff ff 61 c6 85 aa fd ff ff 6d c6 85 ab fd ff ff 20 c6 85 ac fd ff ff 46 c6 } //01 00 
		$a_00_4 = {55 8b ec 81 ec b0 02 00 00 c7 85 b0 fd ff ff 00 00 00 00 eb 0f 8b 85 b0 fd ff ff 83 c0 01 89 85 b0 fd ff ff 83 bd b0 fd ff ff 01 7d 02 eb e6 c7 } //00 00 
	condition:
		any of ($a_*)
 
}