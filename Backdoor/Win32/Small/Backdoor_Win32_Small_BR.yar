
rule Backdoor_Win32_Small_BR{
	meta:
		description = "Backdoor:Win32/Small.BR,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 69 73 69 6e 67 20 55 70 64 61 74 65 } //1 Rising Update
		$a_01_1 = {25 73 5c 25 64 5f 72 65 73 2e 74 6d 70 } //1 %s\%d_res.tmp
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 43 3a 5c 52 65 6d 6f 65 74 65 2e 64 6c 6c 22 20 57 57 57 57 } //1 rundll32.exe "C:\Remoete.dll" WWWW
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\CurrentControlSet\Services\BITS\Parameters
		$a_01_4 = {57 69 6e 64 73 20 55 70 64 61 74 65 } //1 Winds Update
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4b 73 61 66 65 54 72 61 79 2e 65 78 65 } //1 taskkill /f /im KsafeTray.exe
		$a_01_6 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}