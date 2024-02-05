
rule TrojanDownloader_Win32_Redosdru_I_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e 75 } //01 00 
		$a_03_1 = {44 c6 44 24 90 01 01 6c c6 44 24 90 01 01 6c c6 44 24 90 01 01 46 c6 44 24 90 01 01 75 c6 44 24 90 01 01 55 c6 44 24 90 01 01 70 c6 44 24 90 01 01 67 c6 44 24 90 01 01 72 c6 44 24 90 01 01 61 c6 44 24 90 01 01 64 c6 44 24 90 01 01 72 c6 44 24 90 01 01 73 90 00 } //01 00 
		$a_03_2 = {40 00 ff 15 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 83 c4 90 00 } //01 00 
		$a_03_3 = {53 c6 44 24 90 01 01 53 c6 44 24 90 01 01 53 c6 44 24 90 01 01 53 c6 44 24 90 01 01 53 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 01 02 c6 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}