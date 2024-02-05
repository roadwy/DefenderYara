
rule TrojanDownloader_Win32_Artra_A{
	meta:
		description = "TrojanDownloader:Win32/Artra.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 73 74 65 72 69 78 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 32 38 4e 6f 76 44 77 6e 5c 52 65 6c 65 61 73 65 5c 32 38 4e 6f 76 44 77 6e 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}