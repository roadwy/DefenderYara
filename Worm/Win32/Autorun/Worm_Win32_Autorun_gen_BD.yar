
rule Worm_Win32_Autorun_gen_BD{
	meta:
		description = "Worm:Win32/Autorun.gen!BD,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_01_1 = {53 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 3d 00 20 00 41 00 56 00 53 00 45 00 51 00 30 00 31 00 31 00 2e 00 65 00 78 00 65 00 } //1 Shell\open\command = AVSEQ011.exe
		$a_01_2 = {53 00 68 00 65 00 6c 00 6c 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 3d 00 20 00 41 00 56 00 53 00 45 00 51 00 30 00 31 00 31 00 2e 00 65 00 78 00 65 00 20 00 2d 00 65 00 } //1 Shell\explore\command = AVSEQ011.exe -e
		$a_01_3 = {53 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 3d 00 53 00 63 00 61 00 6e 00 20 00 61 00 6c 00 6c 00 20 00 76 00 69 00 72 00 75 00 73 00 } //1 Shell\open=Scan all virus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}