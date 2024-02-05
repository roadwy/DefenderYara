
rule TrojanDownloader_Win32_Kalumino_A{
	meta:
		description = "TrojanDownloader:Win32/Kalumino.A,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 67 00 69 00 72 00 6c 00 6c 00 69 00 75 00 78 00 69 00 61 00 6f 00 77 00 65 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 68 00 6f 00 6d 00 65 00 2f 00 65 00 69 00 70 00 5f 00 6f 00 75 00 72 00 73 00 75 00 72 00 66 00 69 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}