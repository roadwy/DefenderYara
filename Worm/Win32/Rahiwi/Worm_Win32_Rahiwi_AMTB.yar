
rule Worm_Win32_Rahiwi_AMTB{
	meta:
		description = "Worm:Win32/Rahiwi!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {4e 65 78 74 20 76 61 72 69 61 6e 20 77 69 6c 6c 20 62 65 20 72 65 6c 65 61 73 65 64 20 61 2e 73 2e 61 2e 70 } //Next varian will be released a.s.a.p  1
		$a_80_1 = {54 69 77 69 2e 65 78 65 } //Tiwi.exe  1
		$a_80_2 = {4d 79 20 70 72 65 73 65 6e 74 20 74 6f 20 54 69 77 69 } //My present to Tiwi  1
		$a_80_3 = {5f 43 49 63 6f 73 61 64 6a 5f 66 70 74 61 6e } //_CIcosadj_fptan  1
		$a_80_4 = {57 33 32 2f 54 69 77 69 41 } //W32/TiwiA  1
		$a_80_5 = {49 74 27 73 20 46 72 65 65 2e 2e 2e } //It's Free...  1
		$a_80_6 = {7d 45 6e 64 6d 64 69 76 5f 6d 36 34 } //}Endmdiv_m64  1
		$a_80_7 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100) >=7
 
}