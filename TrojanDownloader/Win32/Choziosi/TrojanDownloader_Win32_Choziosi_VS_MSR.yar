
rule TrojanDownloader_Win32_Choziosi_VS_MSR{
	meta:
		description = "TrojanDownloader:Win32/Choziosi.VS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 53 5f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //02 00  CS_installer.exe
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 53 00 74 00 79 00 6c 00 65 00 20 00 48 00 69 00 64 00 64 00 65 00 6e 00 20 00 2d 00 45 00 } //01 00  powershell -ExecutionPolicy Bypass -WindowStyle Hidden -E
		$a_00_2 = {5f 00 6d 00 65 00 74 00 61 00 2e 00 74 00 78 00 74 00 } //01 00  _meta.txt
		$a_01_3 = {64 65 53 63 72 61 6d 62 6c 65 } //00 00  deScramble
		$a_00_4 = {5d 04 00 } //00 aa 
	condition:
		any of ($a_*)
 
}