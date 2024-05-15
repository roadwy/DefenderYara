
rule TrojanDownloader_Win32_Xabduu_ARAA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Xabduu.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4d 00 65 00 74 00 65 00 6f 00 72 00 69 00 74 00 65 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 } //02 00  Meteorite Downloader
		$a_00_1 = {72 00 65 00 67 00 77 00 72 00 69 00 74 00 65 00 } //02 00  regwrite
		$a_00_2 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //02 00  wscript.shell
		$a_01_3 = {6d 6f 64 4d 61 69 6e } //02 00  modMain
		$a_01_4 = {75 72 6c 6d 6f 6e } //00 00  urlmon
	condition:
		any of ($a_*)
 
}