
rule Worm_Win32_Autorun_AGT{
	meta:
		description = "Worm:Win32/Autorun.AGT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 73 65 63 72 65 74 2e 65 78 65 [0-10] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1
		$a_00_1 = {59 6f 75 20 73 79 73 74 65 6d 20 69 6e 66 65 63 74 65 64 20 62 79 20 53 6c 61 73 68 20 57 6f 72 6d 21 } //1 You system infected by Slash Worm!
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Worm_Win32_Autorun_AGT_2{
	meta:
		description = "Worm:Win32/Autorun.AGT,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 4b 00 61 00 72 00 6e 00 65 00 6c 00 33 00 36 00 38 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\system32\Karnel368.exe
		$a_01_1 = {3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00 1a 00 00 00 3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}