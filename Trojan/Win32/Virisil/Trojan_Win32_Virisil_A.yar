
rule Trojan_Win32_Virisil_A{
	meta:
		description = "Trojan:Win32/Virisil.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 54 73 6b 4d 6e 67 72 00 } //1 楋汬獔䵫杮r
		$a_01_1 = {48 00 41 00 52 00 44 00 20 00 44 00 52 00 49 00 56 00 45 00 20 00 76 00 76 00 31 00 31 00 31 00 20 00 43 00 4f 00 52 00 52 00 55 00 50 00 54 00 49 00 4f 00 4e 00 } //1 HARD DRIVE vv111 CORRUPTION
		$a_01_2 = {54 00 68 00 69 00 73 00 20 00 77 00 69 00 6e 00 64 00 6f 00 77 00 20 00 77 00 69 00 6c 00 6c 00 20 00 63 00 6c 00 6f 00 73 00 65 00 20 00 69 00 6e 00 20 00 33 00 20 00 73 00 65 00 63 00 6f 00 75 00 6e 00 64 00 73 00 } //1 This window will close in 3 secounds
		$a_01_3 = {5c 00 76 00 72 00 2e 00 65 00 78 00 65 00 } //1 \vr.exe
		$a_01_4 = {76 00 69 00 72 00 69 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 viriMemory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}