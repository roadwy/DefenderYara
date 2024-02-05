
rule TrojanDownloader_Win32_Nistio_A{
	meta:
		description = "TrojanDownloader:Win32/Nistio.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 65 78 65 00 67 65 74 00 32 30 30 30 00 fd 9a 80 5c 45 78 65 63 50 72 69 2e 64 6c 6c 00 68 69 67 68 00 45 78 65 63 57 61 69 74 00 fd 90 01 01 80 90 00 } //01 00 
		$a_03_1 = {31 30 33 34 00 31 30 33 39 00 31 30 32 38 00 31 32 35 36 00 ff 90 01 01 80 20 00 90 02 0f fd 90 01 01 80 5c 69 6e 65 74 63 2e 64 6c 6c 00 2f 65 6e 64 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}