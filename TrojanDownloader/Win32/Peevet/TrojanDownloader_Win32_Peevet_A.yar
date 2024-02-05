
rule TrojanDownloader_Win32_Peevet_A{
	meta:
		description = "TrojanDownloader:Win32/Peevet.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 00 7a 00 31 00 39 00 2e 00 63 00 6f 00 6d 00 00 00 0a 00 00 00 64 00 6f 00 77 00 6e 00 32 00 00 00 0a 00 00 00 2f 00 6d 00 79 00 69 00 65 00 00 00 14 00 00 00 70 00 61 00 79 00 75 00 73 00 72 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}