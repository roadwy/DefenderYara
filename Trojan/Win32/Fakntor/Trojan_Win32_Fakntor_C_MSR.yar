
rule Trojan_Win32_Fakntor_C_MSR{
	meta:
		description = "Trojan:Win32/Fakntor.C!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 4e 61 72 72 61 74 6f 72 4d 61 69 6e 2e 65 78 65 } //1 c:\windows\system32\NarratorMain.exe
		$a_02_1 = {43 3a 5c 6d 79 57 6f 72 6b 5c 76 63 5c 4e 61 72 72 61 74 6f 72 5f 77 69 6e 64 6f 77 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4e 61 72 72 61 74 6f 72 2e 70 64 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}