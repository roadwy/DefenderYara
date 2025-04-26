
rule Worm_Win32_Dipasik_C_bit{
	meta:
		description = "Worm:Win32/Dipasik.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 65 5f 67 65 74 5f 75 6e 69 78 5f 66 69 6c 65 5f 6e 61 6d 65 00 } //2 楷敮束瑥畟楮彸楦敬湟浡e
		$a_01_1 = {5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //2 \Services\SharedAccess\Parameters\FirewallPolicy\StandardProle\AuthorizedApplications\List
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {71 31 77 32 65 33 72 34 } //1 q1w2e3r4
		$a_01_4 = {73 6d 74 70 3a 2f 2f 25 73 40 25 73 7c 25 73 3a 25 64 7c 25 73 7c 25 73 } //1 smtp://%s@%s|%s:%d|%s|%s
		$a_01_5 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 72 65 70 65 61 74 } //1 if exist "%s" goto repeat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}