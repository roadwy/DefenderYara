
rule TrojanDownloader_Win32_Youaru_A{
	meta:
		description = "TrojanDownloader:Win32/Youaru.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0a 80 f1 11 88 08 40 fe ca 75 f0 } //01 00 
		$a_03_1 = {6a ff 6a 14 e8 90 01 02 ff ff fe cb 75 bc 8b 0e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}