
rule TrojanDownloader_Win32_Small_CBA{
	meta:
		description = "TrojanDownloader:Win32/Small.CBA,SIGNATURE_TYPE_PEHSTR_EXT,63 00 63 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 58 c6 40 fc 90 03 05 05 68 54 54 6a 00 66 6a 00 6a 00 6a 00 68 90 01 04 6a 00 6a 00 e8 0d 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 55 ff d6 ff d0 90 03 01 03 50 89 04 24 e8 0c 00 00 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 55 ff d6 ff d0 90 02 80 43 3a 5c 62 6f 6f 74 2e 69 6e 69 90 00 } //99
	condition:
		((#a_02_0  & 1)*99) >=99
 
}