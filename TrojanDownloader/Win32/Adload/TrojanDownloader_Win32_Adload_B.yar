
rule TrojanDownloader_Win32_Adload_B{
	meta:
		description = "TrojanDownloader:Win32/Adload.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 00 74 00 64 00 73 00 32 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 } //01 00  ztds2.online
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 62 00 6c 00 65 00 62 00 65 00 61 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 64 00 61 00 77 00 64 00 65 00 77 00 2f 00 74 00 72 00 6a 00 67 00 6a 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  http://www.applicablebeam.com/ddawdew/trjgje.exe
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 73 00 65 00 63 00 74 00 6f 00 72 00 61 00 70 00 70 00 6c 00 69 00 61 00 6e 00 63 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 71 00 64 00 65 00 77 00 66 00 77 00 77 00 2f 00 6b 00 64 00 6a 00 61 00 73 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  http://www.sectorappliance.com/qdewfww/kdjase.exe
	condition:
		any of ($a_*)
 
}