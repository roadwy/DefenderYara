
rule TrojanDownloader_Win32_Banload_YM{
	meta:
		description = "TrojanDownloader:Win32/Banload.YM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {7b 65 6e 74 65 72 7d 20 6a 61 20 74 69 6e 68 61 20 76 69 73 74 6f 20 65 73 74 61 73 20 66 6f 74 6f 73 20 61 6e 74 65 73 } //01 00 
		$a_02_1 = {f6 17 47 80 7f ff 00 75 90 01 01 c1 f1 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}