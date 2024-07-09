
rule Trojan_Win32_Brancud_A{
	meta:
		description = "Trojan:Win32/Brancud.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 30 00 05 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff d6 e9 ?? ?? ?? ?? 6a 01 } //10
		$a_00_1 = {45 72 72 6f 72 20 28 6c 6f 67 69 6e 29 3a 20 30 78 31 30 65 30 20 54 68 65 20 6f 70 65 72 61 74 6f 72 20 6f 72 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 68 61 73 20 72 65 66 75 73 65 64 20 74 68 65 20 72 65 71 75 65 73 74 } //10 Error (login): 0x10e0 The operator or administrator has refused the request
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 41 6c 6c 62 65 72 73 74 } //1 Software\Allberst
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 52 75 6e 42 } //1 Software\RunB
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 52 75 6e 43 } //1 Software\RunC
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}