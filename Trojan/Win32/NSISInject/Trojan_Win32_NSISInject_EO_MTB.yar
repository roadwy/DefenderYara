
rule Trojan_Win32_NSISInject_EO_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 ff 75 f4 6a 00 ff 15 } //10
		$a_01_1 = {68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 6a 04 58 c1 e0 00 8b 4d ec ff 34 01 ff 15 } //1
		$a_01_2 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 57 } //1 GetCommandLineW
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
		$a_01_5 = {52 65 61 64 46 69 6c 65 } //1 ReadFile
		$a_01_6 = {47 65 74 46 69 6c 65 53 69 7a 65 } //1 GetFileSize
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}