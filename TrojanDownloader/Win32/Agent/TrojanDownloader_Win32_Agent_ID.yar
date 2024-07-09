
rule TrojanDownloader_Win32_Agent_ID{
	meta:
		description = "TrojanDownloader:Win32/Agent.ID,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {6c 6d 6f 6b 31 32 33 [0-15] 2e 63 6f 6d 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 } //1
		$a_02_1 = {62 61 69 64 75 61 73 70 [0-15] 2e 63 6f 6d 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 } //1
		$a_00_2 = {31 32 32 2e 32 32 34 2e 39 2e 31 35 31 2f 6b 69 6c 6c 73 2e 74 78 74 3f 74 } //1 122.224.9.151/kills.txt?t
		$a_03_3 = {6a 04 99 59 f7 f9 8d 85 ?? ?? ff ff 68 fc 03 00 00 50 8b f2 ff 15 ?? ?? 40 00 } //10
		$a_03_4 = {59 84 c0 59 75 23 68 d0 07 00 00 ff 15 ?? ?? 40 00 } //10
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=22
 
}