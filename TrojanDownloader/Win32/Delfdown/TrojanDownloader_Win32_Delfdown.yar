
rule TrojanDownloader_Win32_Delfdown{
	meta:
		description = "TrojanDownloader:Win32/Delfdown,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 1e 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 53 74 6f 72 6d 32 2e 65 78 65 } //5
		$a_01_1 = {44 3a 5c 42 72 6f 77 73 65 72 73 2e 65 78 65 00 63 6d 64 20 2f 63 20 61 74 74 72 69 62 20 2b 68 20 2b 72 20 2b 73 20 44 3a 5c 42 72 6f 77 73 65 72 73 2e 65 78 65 } //5
		$a_01_2 = {ff ff ff ff 15 00 00 00 68 74 74 70 3a 2f 2f 64 2e 6c 61 69 79 69 62 61 2e 63 6f 6d 2f } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=10
 
}