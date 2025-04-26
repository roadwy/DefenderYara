
rule TrojanDownloader_Win32_Agent_KJ{
	meta:
		description = "TrojanDownloader:Win32/Agent.KJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 19 3c 3e 74 15 81 fe e8 03 00 00 73 0d 8b 4d f4 43 89 5d f8 88 04 0e 46 eb e1 } //1
		$a_03_1 = {83 c4 40 85 c0 74 15 ff ?? ?? 8d ?? ?? ff ff ff 50 e8 ?? ?? ff ff 59 85 c0 59 75 10 ff 45 ec ff 45 f8 83 7d ec 08 0f 8c 74 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}