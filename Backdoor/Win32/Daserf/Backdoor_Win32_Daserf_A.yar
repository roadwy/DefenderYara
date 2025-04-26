
rule Backdoor_Win32_Daserf_A{
	meta:
		description = "Backdoor:Win32/Daserf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {7e 1f 8a 45 10 b1 03 56 8b 75 0c f6 e9 8b 4d 08 2b ce 8a 14 31 32 55 10 2a d0 88 16 46 4f 75 f2 } //3
		$a_01_1 = {3b d7 76 11 81 3c 0e 33 c0 56 a3 8d 04 0e 74 05 46 3b f2 72 ef 8b 78 18 53 } //3
		$a_01_2 = {74 30 3d 25 73 26 74 31 3d } //1 t0=%s&t1=
		$a_01_3 = {70 69 6e 66 73 2e 64 61 74 } //1 pinfs.dat
		$a_01_4 = {2a 46 49 4c 45 4c 49 53 54 2a } //1 *FILELIST*
		$a_01_5 = {49 6e 6a 65 63 74 20 50 72 6f 63 65 73 73 3a 25 73 } //1 Inject Process:%s
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}