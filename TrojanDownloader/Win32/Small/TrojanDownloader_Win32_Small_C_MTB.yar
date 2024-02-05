
rule TrojanDownloader_Win32_Small_C_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 8b ca 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 0f b6 0c 31 0f b6 7c 16 04 33 cf 88 0c 02 75 e0 } //01 00 
		$a_01_1 = {33 d2 6a 1a 5f f7 f7 80 c2 61 88 14 1e 46 3b f1 7c e9 } //00 00 
	condition:
		any of ($a_*)
 
}