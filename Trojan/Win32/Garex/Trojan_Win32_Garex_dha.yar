
rule Trojan_Win32_Garex_dha{
	meta:
		description = "Trojan:Win32/Garex!dha,SIGNATURE_TYPE_PEHSTR,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 49 6e 69 74 44 4c 4c 73 } //1 AppInitDLLs
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 52 65 70 6f 72 74 69 6e 67 } //1 SOFTWARE\Microsoft\Windows Update Reporting
		$a_01_2 = {50 79 74 68 6f 6e 54 68 72 65 61 64 53 74 61 72 74 } //1 PythonThreadStart
		$a_01_3 = {50 79 74 68 6f 6e 54 68 72 65 61 64 53 74 6f 70 } //1 PythonThreadStop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=100
 
}