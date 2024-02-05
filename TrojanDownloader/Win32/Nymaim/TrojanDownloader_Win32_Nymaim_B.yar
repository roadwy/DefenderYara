
rule TrojanDownloader_Win32_Nymaim_B{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c7 45 e6 11 11 11 11 90 02 20 8d 9d fc fc ff ff 90 00 } //01 00 
		$a_03_1 = {c7 03 66 69 6c 65 90 02 20 c7 43 04 6e 61 6d 65 90 02 20 c6 43 08 3d 90 00 } //01 00 
		$a_03_2 = {c7 03 26 64 61 74 90 02 20 66 c7 43 04 61 3d 90 00 } //01 00 
		$a_01_3 = {8b 06 46 08 c0 0f 84 86 f3 ff ff 0d 20 20 20 20 3d 73 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}