
rule Worm_Win32_Autorun_AEQ{
	meta:
		description = "Worm:Win32/Autorun.AEQ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 64 61 6f 6a 69 61 6f 73 68 69 68 61 6f 22 20 3d 20 22 43 3a 5c 5c 57 49 4e 44 4f 57 53 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 44 67 5f 4b 75 6e 2e 65 78 65 22 } //6 "daojiaoshihao" = "C:\\WINDOWS\\system32\\Dg_Kun.exe"
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 75 6b 75 65 6e 35 32 30 2e 77 65 62 31 31 33 2e 68 7a 66 77 71 2e 63 6f 6d 2f 64 61 6f 6a 69 61 6f 73 68 69 68 61 6f 2f 44 67 5f 4b 75 6e 2d 64 6f 63 2e 65 78 65 } //7 http://wukuen520.web113.hzfwq.com/daojiaoshihao/Dg_Kun-doc.exe
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*7) >=13
 
}