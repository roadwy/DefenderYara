
rule TrojanDownloader_Win32_Agent_KX{
	meta:
		description = "TrojanDownloader:Win32/Agent.KX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 a4 76 0d 8a 0c 10 32 c8 88 0c 10 40 3b c3 72 f3 } //1
		$a_03_1 = {c6 44 24 15 3a c6 44 24 16 5c be 03 00 00 00 e8 ?? ?? 00 00 8b d0 8b fb 83 c9 ff 33 c0 f2 ae f7 d1 8b c2 49 33 d2 f7 f1 46 83 fe 09 8a 04 1a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}