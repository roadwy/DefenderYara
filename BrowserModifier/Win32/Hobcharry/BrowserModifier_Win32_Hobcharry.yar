
rule BrowserModifier_Win32_Hobcharry{
	meta:
		description = "BrowserModifier:Win32/Hobcharry,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 14 01 02 04 08 c7 44 24 18 10 20 40 90 c7 44 24 1c ff fe fc f8 c7 44 24 20 f0 e0 c0 80 } //1
		$a_01_1 = {41 44 56 42 48 4f 2e 44 4c 4c 00 } //1
		$a_01_2 = {2e 3f 41 56 43 41 64 76 42 48 4f 43 6c 61 73 73 40 40 } //1 .?AVCAdvBHOClass@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}