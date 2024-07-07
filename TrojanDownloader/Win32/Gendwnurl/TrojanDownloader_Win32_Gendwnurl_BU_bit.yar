
rule TrojanDownloader_Win32_Gendwnurl_BU_bit{
	meta:
		description = "TrojanDownloader:Win32/Gendwnurl.BU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 6d 79 6a 6f 62 20 2f 64 6f 77 6e 6c 6f 61 64 20 2f 70 72 69 6f 72 69 74 79 20 68 69 67 68 20 68 74 74 70 3a 2f 2f 39 32 2e 36 33 2e 31 39 37 2e 36 30 2f 76 6e 63 2e 65 78 65 20 25 74 65 6d 70 25 5c 90 02 20 2e 65 78 65 26 73 74 61 72 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}