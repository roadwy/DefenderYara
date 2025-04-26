
rule TrojanDownloader_Win32_Cavitate_gen_E{
	meta:
		description = "TrojanDownloader:Win32/Cavitate.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 c2 14 0c 00 00 0f af c2 25 ff ff 00 00 89 45 14 5a 8a 14 0e 8a 45 14 32 d0 8b 45 0c 88 11 41 48 } //1
		$a_01_1 = {8d 8c 40 29 87 00 00 8a 04 16 81 e1 ff ff 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}