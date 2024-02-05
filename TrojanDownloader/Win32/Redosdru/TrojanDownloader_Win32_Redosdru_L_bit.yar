
rule TrojanDownloader_Win32_Redosdru_L_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 11 04 90 01 01 34 90 01 01 88 04 11 83 c1 01 3b ce 7c 90 00 } //01 00 
		$a_03_1 = {4b c6 44 24 90 01 01 6f c6 44 24 90 01 01 74 c6 44 24 90 01 01 68 c6 44 24 90 01 01 65 c6 44 24 90 01 01 72 c6 44 24 90 01 01 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}