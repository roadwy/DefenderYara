
rule TrojanDownloader_Win32_Banload_SG{
	meta:
		description = "TrojanDownloader:Win32/Banload.SG,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {66 3d 16 04 0f 85 90 09 05 00 e8 } //3
		$a_02_1 = {5c 52 75 6e [0-03] 22 20 2f 76 20 [0-03] 73 [0-03] 79 [0-03] 73 [0-0a] 20 2f 64 20 22 } //1
		$a_01_2 = {6d 5c 61 74 75 61 6c 69 7a 61 6e 64 6f 2e 64 6c 6c 00 } //1
		$a_03_3 = {68 65 6c 6c [0-02] 33 32 2e [0-03] 44 [0-02] 4c [0-02] 4c 2c 20 43 6f [0-02] 6e 74 [0-02] 72 [0-02] 6f [0-03] 6c 5f 52 } //1
		$a_03_4 = {74 1e 8d 45 ?? 50 b9 01 00 00 00 8b d3 8b 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? e8 ?? ?? ?? ?? 43 4e 0f 85 } //2
		$a_03_5 = {4e 65 74 20 [0-10] 41 75 74 6f 20 [0-20] 47 65 72 61 20 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*1) >=6
 
}