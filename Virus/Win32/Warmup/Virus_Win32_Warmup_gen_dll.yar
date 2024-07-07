
rule Virus_Win32_Warmup_gen_dll{
	meta:
		description = "Virus:Win32/Warmup.gen!dll,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 03 6d c6 43 01 74 c6 43 02 7a c6 43 03 77 c6 43 04 35 c6 43 05 2d c6 43 06 22 c6 43 07 72 c6 43 08 77 c6 43 09 79 c6 43 0a 29 c6 43 0b 6d c6 43 0c 6e c6 43 0d 6c c6 43 0e 66 c6 43 0f 6b c6 43 10 36 c6 43 11 3f c6 43 12 21 c6 43 13 6c c6 43 14 68 c6 43 15 71 c6 43 16 2f c6 43 17 69 c6 43 18 68 c6 43 19 60 c6 43 1a 66 c6 43 1b 23 c6 43 1c 71 c6 43 1d 78 c6 43 1e 7a 8d 45 f0 8b d3 b9 1f 00 00 00 } //10
		$a_01_1 = {64 6c 6c 2e 74 78 74 00 } //1
		$a_01_2 = {43 68 65 63 6b 76 69 70 00 } //1
		$a_01_3 = {55 70 2e 77 6f 72 6d 00 } //1 灕眮牯m
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}