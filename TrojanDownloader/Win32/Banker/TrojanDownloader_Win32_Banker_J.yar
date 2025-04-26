
rule TrojanDownloader_Win32_Banker_J{
	meta:
		description = "TrojanDownloader:Win32/Banker.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {61 73 74 69 2d 74 69 63 69 6e 6f 2e 63 68 2f [0-0f] 2f 4f 70 65 6e 2e 64 6c 6c } //2
		$a_00_1 = {54 43 6f 63 61 69 6e 61 } //1 TCocaina
		$a_00_2 = {46 6f 74 6f 20 43 6f 72 72 6f 6d 70 69 64 61 } //1 Foto Corrompida
		$a_00_3 = {72 65 67 73 76 72 33 32 20 2f 73 20 90 02 0f 5c 57 69 6e 65 74 77 6f 72 6b 2e 64 6c 6c } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Banker_J_2{
	meta:
		description = "TrojanDownloader:Win32/Banker.J,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 74 6f 74 61 6c 76 69 73 69 74 61 2e 6a 70 67 00 } //1
		$a_01_1 = {2e 63 6f 6d 2f 70 63 2e 74 78 74 00 } //1
		$a_01_2 = {2f 63 6f 6e 74 61 64 6f 72 65 2f 65 6e 74 72 61 72 2e 70 68 70 00 } //1
		$a_01_3 = {32 30 38 2e 31 31 35 2e 32 33 38 2e 31 30 39 } //1 208.115.238.109
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}