
rule TrojanDownloader_Win32_MshtaAbuse_C{
	meta:
		description = "TrojanDownloader:Win32/MshtaAbuse.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //01 00  mshta http://
		$a_00_1 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //00 00  mshta https://
	condition:
		any of ($a_*)
 
}