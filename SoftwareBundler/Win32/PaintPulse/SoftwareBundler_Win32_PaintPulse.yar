
rule SoftwareBundler_Win32_PaintPulse{
	meta:
		description = "SoftwareBundler:Win32/PaintPulse,SIGNATURE_TYPE_PEHSTR,46 00 46 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 20 00 2f 00 61 00 66 00 66 00 69 00 64 00 3d 00 61 00 64 00 73 00 63 00 75 00 62 00 65 00 5f 00 75 00 70 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 } //01 00  /install  /affid=adscube_upcleaner
		$a_01_1 = {42 00 75 00 6e 00 64 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  Bundle.exe
		$a_01_2 = {70 00 6f 00 70 00 69 00 73 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //01 00  popisetup.exe
		$a_01_3 = {6b 00 75 00 72 00 75 00 6c 00 75 00 6d 00 2e 00 65 00 78 00 65 00 } //01 00  kurulum.exe
		$a_01_4 = {73 00 6f 00 6d 00 6f 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  somont.exe
		$a_01_5 = {6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 73 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  microsofsetup.exe
		$a_01_6 = {00 67 16 00 } //00 2d 
	condition:
		any of ($a_*)
 
}