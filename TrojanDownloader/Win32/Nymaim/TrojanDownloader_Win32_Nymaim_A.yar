
rule TrojanDownloader_Win32_Nymaim_A{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c7 45 ea 11 11 11 11 90 03 06 09 8d 9d 00 fd ff ff e9 90 16 8d 9d 00 fd ff ff 90 00 } //01 00 
		$a_03_1 = {c7 03 66 69 6c 65 90 03 07 0a c7 43 04 6e 61 6d 65 e9 90 16 c7 43 04 6e 61 6d 65 90 02 10 90 03 04 07 c6 43 08 3d e9 90 16 c6 43 08 3d 90 00 } //01 00 
		$a_03_2 = {c7 03 26 64 61 74 90 03 06 09 66 c7 43 04 61 3d e9 90 16 66 c7 43 04 61 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}