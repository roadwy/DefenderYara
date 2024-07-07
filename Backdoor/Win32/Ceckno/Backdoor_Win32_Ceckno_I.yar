
rule Backdoor_Win32_Ceckno_I{
	meta:
		description = "Backdoor:Win32/Ceckno.I,SIGNATURE_TYPE_PEHSTR,22 00 18 00 0a 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 61 6e 65 } //10 insane
		$a_01_1 = {2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 72 75 20 22 00 } //10
		$a_01_2 = {75 70 5c 2a 2e 73 63 72 } //10 up\*.scr
		$a_01_3 = {73 74 6f 70 61 74 74 61 63 6b } //1 stopattack
		$a_01_4 = {73 61 6e 64 62 6f 78 } //1 sandbox
		$a_01_5 = {64 69 73 61 62 6c 65 72 65 67 69 73 74 72 79 74 6f 6f 6c 73 } //1 disableregistrytools
		$a_01_6 = {00 73 73 79 6e } //1
		$a_01_7 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_8 = {5c 66 69 6c 65 7a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //1 \filezilla\recentservers.xml
		$a_01_9 = {73 65 74 20 63 64 61 75 64 69 6f 20 64 6f 6f 72 20 6f 70 65 6e } //1 set cdaudio door open
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=24
 
}