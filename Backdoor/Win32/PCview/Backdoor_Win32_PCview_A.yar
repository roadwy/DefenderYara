
rule Backdoor_Win32_PCview_A{
	meta:
		description = "Backdoor:Win32/PCview.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 76 65 20 2f 59 20 22 25 73 22 20 22 25 73 22 } //1 move /Y "%s" "%s"
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //2 Applications\iexplore.exe\shell\open\command
		$a_01_2 = {47 6c 6f 62 61 6c 5c 50 43 76 69 65 77 20 25 64 } //3 Global\PCview %d
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 5c 53 65 63 75 72 69 74 79 } //1 SYSTEM\CurrentControlSet\Services\%s\Security
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=4
 
}