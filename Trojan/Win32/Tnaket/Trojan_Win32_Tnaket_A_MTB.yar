
rule Trojan_Win32_Tnaket_A_MTB{
	meta:
		description = "Trojan:Win32/Tnaket.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {40 53 48 83 ec 20 45 33 c0 48 c7 41 18 07 00 00 00 48 8b d9 4c 89 41 10 66 44 89 01 66 44 39 02 74 11 48 83 c8 ff } //1
		$a_81_1 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}