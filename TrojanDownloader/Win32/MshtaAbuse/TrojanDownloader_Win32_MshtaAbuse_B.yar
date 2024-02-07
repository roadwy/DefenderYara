
rule TrojanDownloader_Win32_MshtaAbuse_B{
	meta:
		description = "TrojanDownloader:Win32/MshtaAbuse.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //01 00  mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 } //00 00  http://0
	condition:
		any of ($a_*)
 
}