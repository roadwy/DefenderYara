
rule TrojanDownloader_Win32_Redosdru_J_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 41 00 70 00 70 00 50 00 61 00 74 00 63 00 68 00 90 02 10 2e 00 64 00 6c 00 6c 00 90 00 } //01 00 
		$a_03_1 = {8a 14 39 80 c2 90 01 01 80 f2 90 01 01 88 14 39 41 3b c8 7c 90 00 } //01 00 
		$a_01_2 = {c6 45 f1 6f c6 45 f2 74 c6 45 f3 68 c6 45 f4 65 c6 45 f5 72 c6 45 f6 35 c6 45 f7 39 c6 45 f8 39 } //01 00 
		$a_03_3 = {79 08 4b 81 cb 90 01 04 43 8a 14 0b 30 10 8b 45 fc 40 3b 45 0c 89 45 fc 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}