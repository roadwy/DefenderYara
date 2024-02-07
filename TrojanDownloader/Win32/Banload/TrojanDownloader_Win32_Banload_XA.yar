
rule TrojanDownloader_Win32_Banload_XA{
	meta:
		description = "TrojanDownloader:Win32/Banload.XA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 0f b6 54 32 ff 59 2a d1 f6 d2 e8 90 01 04 8b 55 f0 8d 45 f8 e8 90 01 04 46 4b 75 d9 90 00 } //01 00 
		$a_01_1 = {6c 6f 67 61 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {5b 4c 49 4e 4b } //01 00  [LINK
		$a_01_3 = {5b 6d 6f 64 75 6c 6f } //01 00  [modulo
		$a_01_4 = {5b 53 65 6e 68 61 5d } //00 00  [Senha]
	condition:
		any of ($a_*)
 
}