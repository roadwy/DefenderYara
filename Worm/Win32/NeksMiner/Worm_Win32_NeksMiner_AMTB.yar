
rule Worm_Win32_NeksMiner_AMTB{
	meta:
		description = "Worm:Win32/NeksMiner!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 6b 72 31 73 2e 72 75 2f 6a 61 76 61 72 78 2e 64 61 74 } //http://kr1s.ru/javarx.dat  1
		$a_80_1 = {68 74 74 70 3a 2f 2f 7a 63 6f 70 2e 72 75 2f 6a 61 76 61 72 78 32 2e 64 61 74 } //http://zcop.ru/javarx2.dat  1
		$a_80_2 = {2f 6b 72 31 73 2e 2f 72 75 63 6f 70 2e 2f 7a 63 6f 70 2e 2f 6a 70 67 6f 2e } ///kr1s./rucop./zcop./jpgo.  1
		$a_80_3 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4e 73 43 70 75 43 4e 4d 69 6e 65 72 2a } ///c taskkill /f /im NsCpuCNMiner*  1
		$a_80_4 = {5c 6a 61 76 61 72 78 2e 65 78 65 } //\javarx.exe  1
		$a_00_5 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 70 6f 6f 6c } //1 stratum+tcp://pool
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=6
 
}