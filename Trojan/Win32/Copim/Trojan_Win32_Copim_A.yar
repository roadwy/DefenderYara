
rule Trojan_Win32_Copim_A{
	meta:
		description = "Trojan:Win32/Copim.A,SIGNATURE_TYPE_PEHSTR,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {b9 5e ff ff ff 81 e9 53 ff ff ff f7 f1 89 45 f4 8b 55 0c 03 55 f4 8a 02 88 45 f3 8b ff 8b 4d 08 03 4d f4 8a 55 f3 88 11 8b 45 fc 83 c0 04 83 c0 07 89 45 fc } //10
		$a_01_1 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00 00 00 45 6e 61 62 6c 65 4c 55 41 } //5
		$a_01_2 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 } //1 Elevation:Administrator!new:
		$a_01_3 = {43 6f 70 69 65 72 4d 69 72 63 6f 73 6f 66 74 } //1 CopierMircosoft
		$a_01_4 = {56 42 6f 78 53 65 72 76 69 63 65 2e 65 78 65 } //1 VBoxService.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}