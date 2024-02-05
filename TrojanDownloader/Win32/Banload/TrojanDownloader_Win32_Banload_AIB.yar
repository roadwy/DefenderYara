
rule TrojanDownloader_Win32_Banload_AIB{
	meta:
		description = "TrojanDownloader:Win32/Banload.AIB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 20 2f 73 20 } //04 00 
		$a_01_1 = {23 4c 23 00 ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 0c 00 00 00 72 65 67 73 76 72 33 32 20 2f 73 20 } //00 00 
	condition:
		any of ($a_*)
 
}