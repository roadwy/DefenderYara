
rule TrojanDownloader_Win32_Bancos_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Bancos.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,ffffff98 08 ffffff98 08 05 00 00 ffffffe8 03 "
		
	strings :
		$a_02_0 = {8d 4d ec 8b d3 a1 90 01 04 8b 30 ff 56 0c 8d 45 ec 8b 15 90 01 04 e8 90 01 04 8b 45 ec b2 01 e8 90 01 04 a1 90 01 04 8b 00 e8 90 01 04 68 90 90 01 00 00 e8 90 01 04 4b 83 fb ff 90 00 } //e8 03 
		$a_02_1 = {8d 4d ec 8b d3 a1 90 01 04 8b 30 ff 56 0c 8b 45 ec b2 01 e8 90 01 04 a1 90 01 04 8b 00 e8 90 01 04 68 90 90 01 00 00 e8 90 01 04 4b 83 fb ff 90 00 } //e8 03 
		$a_02_2 = {8b 00 8b 40 30 50 e8 90 01 04 eb 24 6a 05 6a 00 6a 00 8b 45 fc e8 90 01 04 50 68 90 01 04 a1 90 01 04 8b 00 8b 40 30 50 e8 90 00 } //64 00 
		$a_00_3 = {ff ff ff ff 17 00 00 00 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 } //64 00 
		$a_00_4 = {ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}