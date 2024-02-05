
rule TrojanDownloader_Win32_Upranfef_A{
	meta:
		description = "TrojanDownloader:Win32/Upranfef.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6f 70 65 6e 00 90 02 07 68 74 74 70 3a 2f 2f 90 02 30 2f 75 70 64 61 74 2e 65 78 65 00 90 02 07 25 73 5c 25 73 2e 65 78 65 90 00 } //01 00 
		$a_03_1 = {99 59 f7 f9 8d 45 08 50 53 83 c2 61 89 55 08 e8 90 01 04 59 4f 59 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}