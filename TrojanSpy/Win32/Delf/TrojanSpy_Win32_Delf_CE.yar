
rule TrojanSpy_Win32_Delf_CE{
	meta:
		description = "TrojanSpy:Win32/Delf.CE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 73 76 73 63 2e 64 6c 6c } //1 c:\svsc.dll
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 76 65 74 61 2e 69 6e 2f 31 2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 http://sveta.in/1/upload.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}