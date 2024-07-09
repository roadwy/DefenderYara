
rule TrojanDownloader_Win32_Dapato_L{
	meta:
		description = "TrojanDownloader:Win32/Dapato.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {00 5c 76 78 73 33 32 2e 65 78 65 00 00 68 74 74 70 73 3a 2f 2f [0-0f] 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-0f] 2f 76 78 73 33 32 2e 65 78 65 00 } //1
		$a_00_1 = {00 5c 76 78 73 33 32 2e 65 78 65 00 00 6f 70 65 6e 00 } //1 尀硶㍳⸲硥e漀数n
		$a_00_2 = {3a 00 00 00 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00 00 ff ff ff ff 09 00 00 00 45 6e 61 62 6c 65 4c 55 41 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}