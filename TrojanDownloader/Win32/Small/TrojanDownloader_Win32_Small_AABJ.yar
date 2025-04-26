
rule TrojanDownloader_Win32_Small_AABJ{
	meta:
		description = "TrojanDownloader:Win32/Small.AABJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 25 25 25 25 25 25 25 25 25 50 4b 50 4b 20 41 56 20 25 25 25 25 25 25 25 25 25 25 } //1 %%%%%%%%%%PKPK AV %%%%%%%%%%
		$a_02_1 = {5c 64 6f 77 6e 2e 74 78 74 [0-20] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1
		$a_00_2 = {5c 73 79 73 74 65 6d 49 6e 66 6f 6d 61 74 69 6f 6e 73 2e 69 6e 69 } //1 \systemInfomations.ini
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}