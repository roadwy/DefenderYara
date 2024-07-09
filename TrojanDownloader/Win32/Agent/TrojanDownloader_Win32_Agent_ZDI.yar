
rule TrojanDownloader_Win32_Agent_ZDI{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 0c 00 00 00 68 ?? ?? ?? ?? 8b 4d 08 8b 51 38 52 e8 ?? ?? ?? ?? 89 ?? ?? ff ff ff c7 ?? ?? ff ff ff 08 00 00 00 8d ?? ?? ff ff ff 8d ?? ?? ff 15 } //1
		$a_00_1 = {77 00 79 00 66 00 5b 00 31 00 5d 00 2e 00 63 00 73 00 73 00 } //1 wyf[1].css
		$a_00_2 = {64 00 6f 00 77 00 6e 00 } //1 down
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}