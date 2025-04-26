
rule Trojan_Win32_WhisperGate_EC_MTB{
	meta:
		description = "Trojan:Win32/WhisperGate.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {63 6f 70 79 20 76 69 72 75 73 32 2e 65 78 65 20 43 3a 5c 76 69 72 75 73 32 2e 65 78 65 } //1 copy virus2.exe C:\virus2.exe
		$a_81_1 = {52 45 47 20 41 44 44 20 20 48 4b 4c 4d 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 20 2f 76 20 20 44 41 54 4f 53 32 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 REG ADD  HKLM\Software\Microsoft\Windows\CurrentVersion\Run  /v  DATOS2 /t REG_SZ /d
		$a_81_2 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 3a 20 31 30 20 2d 66 } //1 shutdown -s -t: 10 -f
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}