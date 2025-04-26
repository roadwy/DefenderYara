
rule Trojan_Win32_ClipBanker_RPY_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 5e 14 8a 0c b8 2a ca 8b 56 10 88 4d e4 3b d3 73 19 8d 42 01 89 46 10 8b c6 83 fb 10 72 02 8b 06 88 0c 10 c6 44 10 01 00 eb 12 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ClipBanker_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 79 6b 6b 6b 6b 53 } //1 MykkkkS
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {74 72 6f 6e 2e 6d 68 78 69 65 79 69 } //1 tron.mhxieyi
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_4 = {55 73 65 72 2d 41 67 65 6e 74 3a } //1 User-Agent:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}