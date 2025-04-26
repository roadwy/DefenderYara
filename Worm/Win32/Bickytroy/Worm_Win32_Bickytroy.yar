
rule Worm_Win32_Bickytroy{
	meta:
		description = "Worm:Win32/Bickytroy,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 6f 72 75 6e 2e 49 6e 66 } //1 Autorun.Inf
		$a_00_1 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_00_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 54 72 69 63 6b 79 42 6f 79 2e 6d 73 69 0d 0a 00 43 3a 5c } //5
		$a_00_3 = {54 61 73 6b 4d 67 72 2e 65 78 65 00 5c 54 72 69 63 6b 79 42 6f 79 2e 65 78 65 } //5
		$a_03_4 = {83 f8 03 74 13 83 f8 02 74 0e 83 f8 06 74 09 83 f8 04 0f 85 ?? ?? 00 00 80 3b 41 0f 84 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_03_4  & 1)*10) >=12
 
}