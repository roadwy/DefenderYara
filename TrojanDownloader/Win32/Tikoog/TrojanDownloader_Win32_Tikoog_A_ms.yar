
rule TrojanDownloader_Win32_Tikoog_A_ms{
	meta:
		description = "TrojanDownloader:Win32/Tikoog.A!ms,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c1 01 8b 55 90 01 01 8b 02 99 f7 f9 0f af 45 90 01 02 45 90 01 02 45 90 01 03 00 00 90 00 } //01 00 
		$a_03_1 = {99 f7 f9 03 45 90 01 01 89 45 90 01 01 eb cf 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}