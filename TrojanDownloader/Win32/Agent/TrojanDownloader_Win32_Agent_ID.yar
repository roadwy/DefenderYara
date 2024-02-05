
rule TrojanDownloader_Win32_Agent_ID{
	meta:
		description = "TrojanDownloader:Win32/Agent.ID,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {6c 6d 6f 6b 31 32 33 90 02 15 2e 63 6f 6d 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 90 00 } //01 00 
		$a_02_1 = {62 61 69 64 75 61 73 70 90 02 15 2e 63 6f 6d 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 90 00 } //01 00 
		$a_00_2 = {31 32 32 2e 32 32 34 2e 39 2e 31 35 31 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 } //0a 00 
		$a_03_3 = {6a 04 99 59 f7 f9 8d 85 90 01 02 ff ff 68 fc 03 00 00 50 8b f2 ff 15 90 01 02 40 00 90 00 } //0a 00 
		$a_03_4 = {59 84 c0 59 75 23 68 d0 07 00 00 ff 15 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}