
rule TrojanDropper_Win32_FreshCam_A_dha{
	meta:
		description = "TrojanDropper:Win32/FreshCam.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 "
		
	strings :
		$a_41_0 = {31 c0 85 d2 74 1d 0f b6 31 41 4a 69 f6 3c fd 14 31 0f af f6 c1 c6 10 31 c6 0f af f6 c1 c6 10 89 f0 eb df 5e c3 64 } //100
		$a_81_1 = {77 dd 41 b1 8b 5e 08 75 00 00 5d 04 00 00 62 bd 06 80 5c 33 00 00 63 bd 06 80 00 00 01 00 06 00 1d 00 42 61 63 6b 64 6f 6f 72 3a 57 69 6e 36 34 2f 46 72 65 73 68 43 61 6d 2e 41 21 64 68 61 00 00 } //2560
	condition:
		((#a_41_0  & 1)*100+(#a_81_1  & 1)*2560) >=100
 
}