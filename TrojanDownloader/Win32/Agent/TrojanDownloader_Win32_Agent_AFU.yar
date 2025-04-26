
rule TrojanDownloader_Win32_Agent_AFU{
	meta:
		description = "TrojanDownloader:Win32/Agent.AFU,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 32 32 2e 32 31 37 2e 32 34 30 2e 33 30 2f 73 6f 6e 67 2f 67 6f 75 67 6f 75 2e 65 78 65 } //1 222.217.240.30/song/gougou.exe
		$a_01_1 = {32 32 32 2e 32 31 37 2e 32 34 30 2e 33 30 2f 73 6f 6e 67 2f 76 67 61 75 67 61 2e 65 78 65 } //1 222.217.240.30/song/vgauga.exe
		$a_01_2 = {32 32 32 2e 32 31 37 2e 32 34 30 2e 33 30 2f 73 6f 6e 67 2f 70 69 73 6f 6e 2e 65 78 65 } //1 222.217.240.30/song/pison.exe
		$a_01_3 = {00 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 25 73 00 } //1 䐀睯汮慯楤杮┠s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}