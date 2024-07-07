
rule TrojanDropper_Win32_Lespy_gen_A{
	meta:
		description = "TrojanDropper:Win32/Lespy.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 19 00 05 00 00 "
		
	strings :
		$a_00_0 = {7b 65 33 61 37 32 39 64 61 2d 65 61 62 63 2d 64 66 35 30 2d 31 38 34 32 2d 64 66 64 36 38 32 36 34 34 33 31 31 7d } //10 {e3a729da-eabc-df50-1842-dfd682644311}
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 25 73 } //5 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%s
		$a_02_2 = {73 63 72 69 70 74 00 6d 79 63 6c 6f 73 65 65 76 65 6e 74 67 6c 6f 62 61 66 72 61 6d 65 72 6c 31 00 3a 6c 0d 0a 64 65 6c 20 25 73 0d 0a 69 66 90 02 01 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 6c 0d 0a 64 65 6c 20 25 73 00 64 65 6c 74 2e 62 61 74 00 6f 70 65 6e 90 00 } //10
		$a_00_3 = {48 4f 4f 4b 5f 44 4c 4c } //3 HOOK_DLL
		$a_00_4 = {6d 79 63 6c 6f 73 65 65 76 65 6e 74 67 6c 6f 62 61 66 72 61 6d 65 72 6c 31 } //3 mycloseeventglobaframerl1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_02_2  & 1)*10+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3) >=25
 
}