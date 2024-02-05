
rule TrojanDownloader_Win32_Banload_AQL{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 75 62 6b 64 44 } //01 00 
		$a_01_1 = {73 4c 47 67 4c 61 4f 43 56 } //01 00 
		$a_01_2 = {e8 cd fe ff ff 8b 45 fc 8b ce 66 ba c3 84 e8 5b ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}