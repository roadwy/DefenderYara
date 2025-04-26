
rule Backdoor_Win32_Rescoms_B{
	meta:
		description = "Backdoor:Win32/Rescoms.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 63 61 6d 63 61 70 } //1 startcamcap
		$a_01_1 = {61 75 74 6f 66 66 6c 69 6e 65 6c 6f 67 73 } //1 autofflinelogs
		$a_01_2 = {61 75 74 6f 70 73 77 64 61 74 61 } //1 autopswdata
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 66 72 6f 6d 75 72 6c 74 6f 66 69 6c 65 } //1 downloadfromurltofile
		$a_01_4 = {73 74 61 72 74 6f 6e 6c 69 6e 65 6b 6c } //1 startonlinekl
		$a_01_5 = {67 65 74 73 63 72 73 6c 69 73 74 } //1 getscrslist
		$a_01_6 = {73 63 72 65 65 6e 73 68 6f 74 64 61 74 61 } //1 screenshotdata
		$a_01_7 = {43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 43 26 43 21 } //5 Connected to C&C!
		$a_01_8 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a } //5 Remcos_Mutex_Inj
		$a_01_9 = {42 72 65 61 6b 69 6e 67 2d 53 65 63 75 72 69 74 79 2e 4e 65 74 } //5 Breaking-Security.Net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=11
 
}