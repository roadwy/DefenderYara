
rule TrojanDownloader_Win32_Agent_ZBB{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZBB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 51 ff 15 ?? ?? ?? ?? 8d 94 24 10 01 00 00 52 ff d6 b9 41 00 00 00 33 c0 8d bc 24 14 02 00 00 f3 ab 8d 44 24 0c 8d 8c 24 14 02 00 00 50 } //10
		$a_02_1 = {8d 84 24 10 01 00 00 83 e1 03 50 f3 a4 68 f0 00 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 25 07 00 00 80 79 05 48 83 c8 f8 40 83 c0 04 } //10
		$a_00_2 = {2e 64 6c 6c 00 46 69 6e 64 00 53 65 72 76 69 63 65 4d 61 69 6e } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1) >=11
 
}