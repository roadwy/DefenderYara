
rule TrojanDownloader_Win32_Banload_gen_J{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 54 1a ff 2b d3 83 ea 3f e8 90 01 02 ff ff 8b 55 f4 8d 45 f8 e8 90 01 02 ff ff 43 4e 75 dc 90 00 } //01 00 
		$a_01_1 = {69 6d 67 6c 6f 67 2e 78 6d 6c } //01 00 
		$a_01_2 = {6f 72 6b 75 74 6b 75 74 2e 78 6d 6c } //00 00 
	condition:
		any of ($a_*)
 
}