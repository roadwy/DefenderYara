
rule TrojanDownloader_Win32_Agent_ZDH{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 30 64 89 20 68 fa 00 00 00 8d 85 fc fe ff ff 50 e8 90 01 04 8d 85 f8 fe ff ff 8d 95 fc fe ff ff b9 00 01 00 00 e8 90 01 04 8b 95 f8 fe ff ff b8 90 01 04 b9 90 01 04 e8 90 01 04 8d 85 f4 fe ff ff 8d 95 fc fe ff ff b9 00 01 00 00 e8 90 01 04 8b 95 f4 fe ff ff 8d 45 fc b9 90 01 04 e8 90 01 04 8b 45 fc 90 00 } //01 00 
		$a_00_1 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  NtQuerySystemInformation
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_3 = {4c 75 6f 58 75 65 } //01 00  LuoXue
		$a_00_4 = {62 65 65 70 2e 73 79 73 } //01 00  beep.sys
		$a_00_5 = {73 62 6c 2e 73 79 73 } //00 00  sbl.sys
	condition:
		any of ($a_*)
 
}