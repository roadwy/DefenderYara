
rule TrojanDownloader_Win32_Agent_U{
	meta:
		description = "TrojanDownloader:Win32/Agent.U,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //01 00 
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_01_2 = {44 69 73 61 62 6c 65 53 63 72 69 70 74 44 65 62 75 67 67 65 72 49 45 } //01 00 
		$a_01_3 = {53 65 4c 6f 61 64 44 72 69 76 65 72 50 72 69 76 69 6c 65 67 65 } //01 00 
		$a_01_4 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00 
		$a_01_5 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00 
		$a_02_6 = {83 c4 08 8d 8d fc fb ff ff 89 8d ec fb ff ff c7 85 f0 fb ff ff 90 01 04 8b 95 f0 fb ff ff 89 95 f0 fb ff ff c7 85 f4 fb ff ff 00 00 00 00 c7 85 f8 fb ff ff 00 00 00 00 8d 85 ec fb ff ff 50 ff 15 90 01 04 e9 82 01 00 00 68 90 01 04 6a 01 6a 00 ff 15 90 01 04 89 85 e0 fb ff ff ff 15 90 01 04 89 85 e8 fb ff ff 81 bd e8 fb ff ff b7 00 00 00 75 14 8b 8d e0 fb ff ff 51 ff 15 90 01 04 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}