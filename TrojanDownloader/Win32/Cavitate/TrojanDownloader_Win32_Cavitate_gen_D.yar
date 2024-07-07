
rule TrojanDownloader_Win32_Cavitate_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Cavitate.gen!D,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 1c c5 00 00 00 00 2b d8 c1 e3 04 8d 44 03 81 8a 1c 0e 25 ff 00 00 00 32 d8 88 19 41 4f 75 e0 5f c6 04 2a 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}