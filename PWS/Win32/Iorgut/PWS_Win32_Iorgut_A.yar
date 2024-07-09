
rule PWS_Win32_Iorgut_A{
	meta:
		description = "PWS:Win32/Iorgut.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 16 00 06 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 (81|83) ea [0-04] e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 43 4e 75 } //10
		$a_00_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 \Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {66 72 6d 70 72 69 6e 63 69 70 61 6c } //1 frmprincipal
		$a_00_3 = {74 69 74 75 6c 6f 3d 49 6f 72 67 75 74 65 } //1 titulo=Iorgute
		$a_00_4 = {66 72 79 73 79 2e 6e 65 74 } //1 frysy.net
		$a_00_5 = {56 65 72 69 66 69 63 61 6e 64 6f 52 65 73 6f 6c } //1 VerificandoResol
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=22
 
}