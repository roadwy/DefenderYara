
rule Worm_Win32_Autorun_HT{
	meta:
		description = "Worm:Win32/Autorun.HT,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 %c:\autorun.inf
		$a_01_1 = {5c 63 6f 6d 6d 61 6e 64 2e 63 6f 6d } //1 \command.com
		$a_01_2 = {25 73 5c 65 78 70 6c 6f 72 65 72 20 25 63 3a } //1 %s\explorer %c:
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 52 45 43 59 43 4c 45 52 5c 25 73 } //1 shellexecute=RECYCLER\%s
		$a_01_4 = {25 73 20 2f 63 20 72 64 20 25 63 3a 5c 52 45 43 59 43 4c 45 52 5c 25 73 20 2f 73 2f 71 } //1 %s /c rd %c:\RECYCLER\%s /s/q
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}