
rule TrojanDownloader_Win32_Cavitate_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Cavitate.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c3 60 0f af c3 25 ff ff 00 00 89 45 14 8a 04 0a 8a 5d 14 32 c3 88 01 8b 45 0c 41 48 } //1
		$a_01_1 = {8b 6c 24 0c 83 fd 01 73 04 33 c0 5d c3 83 fd 05 76 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}