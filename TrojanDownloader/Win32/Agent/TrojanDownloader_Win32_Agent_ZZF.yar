
rule TrojanDownloader_Win32_Agent_ZZF{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZZF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {64 a1 18 00 00 00 8b 40 30 0f b6 40 02 85 c0 0f 85 b7 02 00 00 31 c0 40 50 50 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 57 } //1
		$a_03_1 = {68 00 20 00 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 85 c0 75 05 e9 ?? 00 00 00 83 3d ?? ?? 40 00 00 74 41 } //1
		$a_00_2 = {75 70 64 61 74 65 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 update.microsoft.com
		$a_00_3 = {41 67 61 76 61 44 77 6e 6c } //1 AgavaDwnl
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}