
rule TrojanProxy_Win32_Bedri_C{
	meta:
		description = "TrojanProxy:Win32/Bedri.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff 73 c6 85 90 01 02 ff ff 30 c6 85 90 01 02 ff ff 63 c6 85 90 01 02 ff ff 6b c6 85 90 01 02 ff ff 73 c6 85 90 01 02 ff ff 39 c6 85 90 01 02 ff ff 72 c6 85 90 01 02 ff ff 6f c6 85 90 01 02 ff ff 78 90 00 } //1
		$a_03_1 = {ff ff 62 c6 85 90 01 02 ff ff 38 c6 85 90 01 02 ff ff 65 c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 72 c6 85 90 01 02 ff ff 69 c6 85 90 01 02 ff ff 33 c6 85 90 01 02 ff ff 68 c6 85 90 01 02 ff ff 38 c6 85 90 01 02 ff ff 6e c6 85 90 01 02 ff ff 62 90 00 } //1
		$a_01_2 = {3c 62 6f 64 79 3e 3c 68 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 68 31 3e 3c 2f 62 6f 64 79 3e } //1 <body><h1>403 Forbidden</h1></body>
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanProxy_Win32_Bedri_C_2{
	meta:
		description = "TrojanProxy:Win32/Bedri.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_03_0 = {b9 06 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab 66 ab 8d 85 90 01 02 ff ff 50 6a 00 68 03 00 1f 00 ff 15 90 09 0e 00 c6 85 90 01 02 ff ff 32 c6 85 90 01 02 ff ff 00 90 00 } //2
		$a_03_1 = {0f be 08 83 f9 2f 74 0b 8b 55 90 01 01 83 ea 01 89 55 90 01 01 eb ea 90 00 } //1
		$a_03_2 = {ff ff 73 c6 85 90 01 02 ff ff 30 c6 85 90 01 02 ff ff 63 c6 85 90 01 02 ff ff 6b c6 85 90 01 02 ff ff 73 c6 85 90 01 02 ff ff 39 90 00 } //1
		$a_01_3 = {25 73 69 65 78 70 6c 6f 72 6f 72 2e 65 78 65 } //1 %siexploror.exe
		$a_01_4 = {67 68 65 00 49 53 41 4c 49 56 45 00 63 63 31 00 } //1 桧e卉䱁噉E捣1
		$a_00_5 = {66 75 63 6b 20 79 6f 75 72 20 6d 75 6d 2c 20 6e 6f 64 33 32 00 } //1
		$a_01_6 = {78 63 76 00 65 63 68 6f 20 6f 66 66 0d 0a 73 74 61 72 74 20 22 66 64 63 64 66 22 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*2) >=4
 
}