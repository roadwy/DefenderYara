
rule TrojanDownloader_Win32_MshtaAbuse_B{
	meta:
		description = "TrojanDownloader:Win32/MshtaAbuse.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 } //1 http://0
		$a_00_2 = {6d 00 73 00 65 00 64 00 67 00 65 00 77 00 65 00 62 00 76 00 69 00 65 00 77 00 32 00 2e 00 65 00 78 00 65 00 } //-1000 msedgewebview2.exe
		$a_00_3 = {69 00 66 00 20 00 66 00 61 00 6c 00 73 00 65 00 20 00 3d 00 3d 00 20 00 66 00 61 00 6c 00 73 00 65 00 20 00 65 00 63 00 68 00 6f 00 } //-1000 if false == false echo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-1000+(#a_00_3  & 1)*-1000) >=2
 
}