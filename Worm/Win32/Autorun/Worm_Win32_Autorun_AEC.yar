
rule Worm_Win32_Autorun_AEC{
	meta:
		description = "Worm:Win32/Autorun.AEC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 41 5f 4c 6f 6f 70 46 69 65 6c 64 25 3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //1 %A_LoopField%:\AutoRun.inf
		$a_01_1 = {6f 70 65 6e 3d 66 61 63 65 62 6f 6f 6b 5f 70 68 6f 74 6f 2e 65 78 65 } //1 open=facebook_photo.exe
		$a_01_2 = {25 41 5f 57 69 6e 44 69 72 25 5c 65 6e 63 6f 64 65 72 2e 74 78 74 } //1 %A_WinDir%\encoder.txt
		$a_01_3 = {4d 53 49 6e 66 6f 5c 52 65 63 79 63 6c 65 64 2e 73 63 72 } //1 MSInfo\Recycled.scr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}