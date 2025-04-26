
rule Trojan_Win32_Lostpy_A_bit{
	meta:
		description = "Trojan:Win32/Lostpy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 6c 6f 73 74 65 72 2e 65 78 65 } //1 C:\WINDOWS\system32\loster.exe
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 54 65 72 73 74 } //1 software\microsoft\windows\CurrentVersion\Run\Terst
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}