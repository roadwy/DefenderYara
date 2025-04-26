
rule Trojan_Win32_VBObfuse_RA_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //1 C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB
		$a_01_1 = {43 3a 5c 41 72 63 68 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //1 C:\Archivos de programa\Microsoft Visual Studio\VB98\VB6.OLB
		$a_00_2 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 45 00 6a 00 65 00 63 00 75 00 74 00 61 00 62 00 6c 00 65 00 73 00 5c 00 43 00 6f 00 76 00 65 00 43 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //2 \Programas\Ejecutables\CoveCost.exe
		$a_00_3 = {5c 00 53 00 65 00 74 00 75 00 70 00 5c 00 52 00 75 00 6e 00 54 00 69 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //2 \Setup\RunTime.exe
		$a_00_4 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3a 00 20 00 44 00 45 00 50 00 55 00 52 00 41 00 44 00 4f 00 52 00 54 00 52 00 58 00 46 00 44 00 2e 00 45 00 58 00 45 00 } //2 Program: DEPURADORTRXFD.EXE
		$a_00_5 = {44 00 65 00 70 00 75 00 72 00 61 00 54 00 72 00 46 00 44 00 2e 00 65 00 78 00 65 00 } //2 DepuraTrFD.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=5
 
}