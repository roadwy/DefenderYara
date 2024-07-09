
rule TrojanDownloader_Win32_Banload_ZEZ_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 77 77 2e 6d 6f 64 [0-10] 6c 6f 6a 61 62 69 67 69 6e 66 6f 72 6d 61 74 69 63 61 2e 69 6e 66 6f } //1
		$a_01_1 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74 } //1
		$a_01_2 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}