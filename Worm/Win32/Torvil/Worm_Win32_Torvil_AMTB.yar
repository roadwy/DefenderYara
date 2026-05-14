
rule Worm_Win32_Torvil_AMTB{
	meta:
		description = "Worm:Win32/Torvil!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 6f 6e 74 65 6e 74 2d 4c 6f 63 61 74 69 6f 6e 3a 46 69 6c 65 3a 2f 2f 74 6f 72 76 69 6c 2e 65 78 65 } //Content-Location:File://torvil.exe  1
		$a_80_1 = {74 6f 72 76 69 6c 2e 70 69 66 } //torvil.pif  1
		$a_80_2 = {4f 6e 65 4c 65 76 65 6c 44 65 65 70 65 72 5c 54 6f 72 76 69 6c 44 42 } //OneLevelDeeper\TorvilDB  1
		$a_80_3 = {73 70 6f 6f 6c 75 78 2e 65 78 65 } //spoolux.exe  1
		$a_80_4 = {21 46 69 6c 65 3a 2f 2f 74 6f 72 76 69 6c 2e 65 78 65 } //!File://torvil.exe  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}