
rule TrojanDownloader_Win32_MshtaAbuse_C{
	meta:
		description = "TrojanDownloader:Win32/MshtaAbuse.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1 mshta http://
		$a_00_1 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //1 mshta https://
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}