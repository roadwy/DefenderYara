
rule Backdoor_Win32_Agent_AXA{
	meta:
		description = "Backdoor:Win32/Agent.AXA,SIGNATURE_TYPE_PEHSTR,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {49 6c 6f 76 65 62 65 69 62 65 69 } //3 Ilovebeibei
		$a_01_1 = {73 25 5c 70 6d 65 54 5c 53 57 4f 44 4e 49 57 5c 3a 43 } //3 s%\pmeT\SWODNIW\:C
		$a_01_2 = {5c 53 74 61 72 74 75 70 5c 33 36 4f 50 47 2e 63 6f 6d } //3 \Startup\36OPG.com
		$a_01_3 = {5c 54 65 6d 70 5c 68 78 31 30 37 2e 74 6d 70 } //3 \Temp\hx107.tmp
		$a_01_4 = {5c 48 65 6c 70 5c 52 55 4e 44 4c 4c 33 32 2e 65 78 65 } //2 \Help\RUNDLL32.exe
		$a_01_5 = {5c 33 36 30 72 70 5c } //1 \360rp\
		$a_01_6 = {5c 33 36 30 53 65 6c 66 50 72 6f 74 65 63 74 69 6f 6e 5c } //1 \360SelfProtection\
		$a_01_7 = {52 73 74 72 61 79 2e 65 78 65 } //1 Rstray.exe
		$a_01_8 = {46 75 63 6b } //1 Fuck
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}