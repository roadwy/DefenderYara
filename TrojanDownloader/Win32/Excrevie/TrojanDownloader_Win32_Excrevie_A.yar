
rule TrojanDownloader_Win32_Excrevie_A{
	meta:
		description = "TrojanDownloader:Win32/Excrevie.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 63 20 63 72 65 61 74 65 20 43 48 4e 47 54 53 76 63 20 62 69 6e 50 61 74 68 3d 20 22 63 3a 5c 65 78 65 72 76 69 63 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f } //01 00  sc create CHNGTSvc binPath= "c:\exervice.exe http://
		$a_01_1 = {73 63 20 73 74 61 72 74 20 70 72 6f 6e 74 73 70 6f 6f 6c 65 72 } //01 00  sc start prontspooler
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 2f 78 70 61 63 6b } //00 00  download/xpack
	condition:
		any of ($a_*)
 
}