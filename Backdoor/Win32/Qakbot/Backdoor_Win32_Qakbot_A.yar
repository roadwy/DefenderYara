
rule Backdoor_Win32_Qakbot_A{
	meta:
		description = "Backdoor:Win32/Qakbot.A,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 69 6a 6b 2e 63 63 2f 63 67 69 2d 62 69 6e 2f 6a 6c 2f 6a 6c 6f 61 64 65 72 2e 70 6c 3f 6c 6f 61 64 66 69 6c 65 3d 71 } //10 http://ijk.cc/cgi-bin/jl/jloader.pl?loadfile=q
		$a_00_1 = {48 65 6c 6c 6f 39 39 39 57 30 72 6c 64 37 37 37 } //10 Hello999W0rld777
		$a_00_2 = {5f 71 62 6f 74 6e 74 69 2e 65 78 65 } //10 _qbotnti.exe
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 6f 6e 63 65 } //5 SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 5c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 5c 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 5c 52 75 6e 6f 6e 63 65 } //5 SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce
		$a_01_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=37
 
}