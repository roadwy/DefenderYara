
rule TrojanDownloader_Win32_Banload_AJQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 d0 fb 44 00 e8 48 7e ff ff ba 90 01 02 44 00 b8 90 01 02 44 00 e8 b9 fe ff ff 84 c0 74 0c 33 d2 b8 90 01 02 44 00 e8 49 ff ff ff 90 00 } //01 00 
		$a_03_1 = {a1 bc df 44 00 8b 00 e8 90 01 02 ff ff c3 90 02 02 ff ff ff ff 90 01 01 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 90 02 02 5c 90 02 08 2e 65 78 65 00 90 02 03 ff ff ff ff 90 01 01 00 00 00 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}