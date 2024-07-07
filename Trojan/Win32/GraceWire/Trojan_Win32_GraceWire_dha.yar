
rule Trojan_Win32_GraceWire_dha{
	meta:
		description = "Trojan:Win32/GraceWire!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 73 00 65 00 6c 00 6c 00 69 00 6e 00 67 00 2d 00 63 00 6f 00 72 00 70 00 2e 00 63 00 6f 00 6d 00 } //3 reselling-corp.com
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 } //1 shutdown /r /t
		$a_01_2 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 } //1 Cookie:
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 74 68 65 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 } //1 Failed to open the target process
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 6a 65 63 74 20 74 68 65 20 44 4c 4c } //1 Failed to inject the DLL
		$a_01_5 = {67 65 74 61 6e 64 67 6f 64 6c 6c 5f 57 69 6e 33 32 2e 64 6c 6c } //2 getandgodll_Win32.dll
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=4
 
}