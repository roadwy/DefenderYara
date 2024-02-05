
rule TrojanDownloader_Win64_Hoogbot_A{
	meta:
		description = "TrojanDownloader:Win64/Hoogbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 68 6f 62 90 01 05 6f 74 90 00 } //01 00 
		$a_03_1 = {6a 61 76 61 2d 73 64 6b 90 02 10 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}