
rule Worm_Win32_SillyShareCopy_G{
	meta:
		description = "Worm:Win32/SillyShareCopy.G,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
		$a_01_1 = {54 4f 4f 4c 54 49 50 53 5f 43 4c 41 53 53 33 32 } //1 TOOLTIPS_CLASS32
		$a_01_2 = {61 76 70 2e 65 78 65 00 64 65 6c 20 25 30 0d 0a } //1
		$a_01_3 = {67 6f 74 6f 20 3a 73 65 6c 66 6b 69 6c 6c 0d 0a } //1
		$a_01_4 = {25 63 3a 5c 00 00 00 00 2e 44 4c 4c } //1
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //5 WriteProcessMemory
		$a_01_6 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //5 CreateRemoteThread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=14
 
}