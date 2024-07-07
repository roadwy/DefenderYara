
rule TrojanDropper_Win32_Datsup_A{
	meta:
		description = "TrojanDropper:Win32/Datsup.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 64 00 61 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\dasvchost.exe
		$a_01_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 64 00 74 00 61 00 72 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\sdtartup.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}