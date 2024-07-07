
rule Worm_Win32_Autorun_EN{
	meta:
		description = "Worm:Win32/Autorun.EN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 Autorun.inf
		$a_00_1 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_00_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 52 65 63 79 63 6c 65 64 2e 65 78 65 20 2d 65 } //1 shell\open\Command=Recycled.exe -e
		$a_03_3 = {ff 15 40 70 40 00 6a 07 8d 90 01 03 50 ff d7 68 90 01 04 6a 68 6a 00 ff 15 44 70 40 00 8b f0 85 f6 0f 90 01 03 00 00 56 6a 00 ff 15 48 70 40 00 56 6a 00 90 01 04 ff 15 4c 70 40 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}