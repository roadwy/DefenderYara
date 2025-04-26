
rule Trojan_Win32_Ransirac_G{
	meta:
		description = "Trojan:Win32/Ransirac.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 software\Microsoft\Windows\CurrentVersion\Run
		$a_02_1 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e [0-20] 73 68 65 6c 6c } //1
		$a_02_2 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e [0-20] 75 73 65 72 69 6e 69 74 } //1
		$a_01_3 = {67 65 6d 61 5c 67 65 6d 61 2e 65 78 65 00 } //1
		$a_01_4 = {2f 7a 61 6c 75 70 61 2f 3f 69 64 3d } //1 /zalupa/?id=
		$a_01_5 = {42 55 54 54 4f 4e 5f 45 4e 54 45 52 5f 53 45 52 49 41 4c } //1 BUTTON_ENTER_SERIAL
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}