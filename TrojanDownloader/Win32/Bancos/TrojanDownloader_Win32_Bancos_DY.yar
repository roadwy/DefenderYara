
rule TrojanDownloader_Win32_Bancos_DY{
	meta:
		description = "TrojanDownloader:Win32/Bancos.DY,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 74 61 6d 61 72 65 73 2e 63 6f 6d 2f 73 70 61 69 6e 2f 41 44 4f 42 45 52 45 41 44 45 52 39 30 2e 65 78 65 00 ff ff ff ff 07 00 00 00 41 50 50 44 41 54 41 00 ff ff ff ff 12 00 00 00 5c 41 44 4f 42 45 52 45 41 44 45 52 39 30 2e 65 78 65 00 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00 
	condition:
		any of ($a_*)
 
}