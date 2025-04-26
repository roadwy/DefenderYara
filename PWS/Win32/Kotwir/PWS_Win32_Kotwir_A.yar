
rule PWS_Win32_Kotwir_A{
	meta:
		description = "PWS:Win32/Kotwir.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 Toolhelp32ReadProcessMemory
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 65 78 6f 6e 5c 4b 69 6e 67 64 6f 6d 20 6f 66 20 74 68 65 20 57 69 6e 64 73 } //1 Software\Nexon\Kingdom of the Winds
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 57 69 7a 65 74 5c 4d 61 70 6c 65 53 74 6f 72 79 } //1 SOFTWARE\Wizet\MapleStory
		$a_01_3 = {3b 50 61 73 73 77 6f 72 64 3a 00 00 ff ff ff ff 11 00 00 00 3b 53 65 63 6f 6e 64 20 50 61 73 73 77 6f 72 64 3a 00 } //5
		$a_01_4 = {26 73 74 72 50 61 73 73 77 6f 72 64 3d } //5 &strPassword=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=7
 
}