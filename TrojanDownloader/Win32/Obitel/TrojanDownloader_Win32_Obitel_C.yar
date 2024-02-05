
rule TrojanDownloader_Win32_Obitel_C{
	meta:
		description = "TrojanDownloader:Win32/Obitel.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 38 6e 74 1f 80 bf 90 01 02 00 00 6f 74 16 80 bf 90 01 02 00 00 6e 74 0d 80 bf 90 01 02 00 00 65 74 04 50 ff 57 90 00 } //01 00 
		$a_01_1 = {8b 45 08 c1 e8 1c 3c 0a 0f b6 c0 73 05 83 c0 30 eb 03 83 c0 57 c1 65 08 04 88 04 0a 42 83 fa 08 7c de } //01 00 
		$a_01_2 = {3f 68 61 73 68 3d 00 00 68 74 74 70 3a 2f 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}