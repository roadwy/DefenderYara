
rule TrojanDownloader_Win32_Rezona_RA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rezona.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 6f 57 65 52 73 48 65 4c 6c } //1 PoWeRsHeLl
		$a_02_1 = {28 6e 45 77 2d 4f 62 4a 65 43 74 20 4e 65 54 2e 57 65 62 43 6c 49 65 4e 74 29 2e 44 6f 57 6e 4c 6f 41 64 46 69 4c 65 28 27 68 74 74 70 3a 2f 2f [0-10] 2f [0-20] 2e [0-04] 27 2c 20 27 [0-20] 5c 90 1b 01 2e 90 1b 02 27 29 20 26 } //5
		$a_02_2 = {28 77 67 65 74 20 27 68 74 74 70 [0-10] 2f [0-0a] 27 20 2d 4f 75 74 46 69 6c 65 20 [0-02] 5c [0-0a] 5c [0-0a] 2e 65 78 65 29 } //5
		$a_02_3 = {73 54 61 52 74 20 [0-02] 5c [0-0a] 5c [0-0a] 5c [0-20] 2e } //4
		$a_02_4 = {70 4f 77 45 72 53 68 45 6c 4c 20 2d 77 49 6e 20 31 20 2d 63 20 22 49 45 58 20 28 4e 65 57 2d 6f 42 6a 45 63 54 20 6e 45 74 2e 57 65 42 43 6c 49 65 4e 74 29 2e 44 6f 57 6e 4c 6f 41 64 53 74 52 69 4e 67 28 27 68 74 74 70 3a 2f 2f [0-10] 2f [0-20] 2e [0-04] 27 29 22 } //4
		$a_02_5 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 50 61 73 73 20 2d 46 69 6c 65 20 [0-20] 20 26 20 53 54 41 52 54 20 2f 4d 49 4e 20 [0-20] 2e 65 78 65 } //4
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5+(#a_02_3  & 1)*4+(#a_02_4  & 1)*4+(#a_02_5  & 1)*4) >=10
 
}