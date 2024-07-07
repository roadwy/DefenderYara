
rule Worm_Win32_Autorun_RL{
	meta:
		description = "Worm:Win32/Autorun.RL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f8 02 74 18 53 e8 90 01 04 83 f8 05 75 0d 90 00 } //1
		$a_01_1 = {73 68 65 6c 6c 2f 61 75 74 6f 70 6c 61 79 2f 63 6f 6d 6d 61 6e 64 3d 4e 65 77 46 6f 6c 64 65 72 2e 65 78 65 } //1 shell/autoplay/command=NewFolder.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}