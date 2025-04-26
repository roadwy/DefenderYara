
rule Trojan_Win32_Autrino_A{
	meta:
		description = "Trojan:Win32/Autrino.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 5f 75 5f 54 6a 5f 4e 6f 31 32 33 33 32 31 45 78 65 } //1 A_u_Tj_No123321Exe
		$a_01_1 = {63 73 62 6f 79 62 69 6e 64 2e 61 75 } //1 csboybind.au
		$a_01_2 = {54 68 75 6e 64 65 72 50 6c 61 74 66 6f 72 6d 2e 65 78 65 } //1 ThunderPlatform.exe
		$a_01_3 = {73 74 6f 72 6d 6c 69 76 2e 65 78 65 } //1 stormliv.exe
		$a_01_4 = {63 73 62 6f 79 44 56 44 2e 64 6c 6c } //1 csboyDVD.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}