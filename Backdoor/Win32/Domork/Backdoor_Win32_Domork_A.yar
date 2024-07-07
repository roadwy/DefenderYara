
rule Backdoor_Win32_Domork_A{
	meta:
		description = "Backdoor:Win32/Domork.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //1 software\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 SOFTWARE\Classes\HTTP\shell\open\command
		$a_00_2 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 25 73 } //1 SYSTEM\ControlSet001\Services\%s
		$a_00_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 00 } //1
		$a_01_4 = {44 6f 4d 61 69 6e 57 6f 72 6b } //1 DoMainWork
		$a_00_5 = {6d 79 74 68 72 65 61 64 69 64 3d 25 64 3b 6d 79 73 65 72 76 65 72 61 64 64 72 3d 25 73 3b 6d 79 73 65 72 76 65 72 70 6f 72 74 3d 25 64 } //1 mythreadid=%d;myserveraddr=%s;myserverport=%d
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}