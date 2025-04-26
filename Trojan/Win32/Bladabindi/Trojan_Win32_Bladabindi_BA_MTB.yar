
rule Trojan_Win32_Bladabindi_BA_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.BA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 75 62 65 48 79 67 72 6f 73 74 61 74 2e 64 6c 6c } //1 TubeHygrostat.dll
		$a_01_1 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 54 75 62 65 48 79 67 72 6f 73 74 61 74 2c 58 65 72 6f 70 68 79 74 65 73 } //1 %%\rundll32.exe TubeHygrostat,Xerophytes
		$a_01_2 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 68 6f 6c 65 63 79 73 74 6f 73 74 6f 6d 79 2c 53 68 6f 72 65 6c 69 6e 65 73 } //1 %%\rundll32.exe Cholecystostomy,Shorelines
		$a_01_3 = {43 68 6f 6c 65 63 79 73 74 6f 73 74 6f 6d 79 2e 64 6c 6c } //1 Cholecystostomy.dll
		$a_01_4 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 72 65 61 74 69 6e 69 6e 65 2c 53 68 6f 72 65 6c 69 6e 65 73 } //1 %%\rundll32.exe Creatinine,Shorelines
		$a_01_5 = {43 72 65 61 74 69 6e 69 6e 65 2e 64 6c 6c } //1 Creatinine.dll
		$a_01_6 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 68 69 6c 62 6c 61 69 6e 2c 50 72 65 74 6f 72 } //1 %%\rundll32.exe Chilblain,Pretor
		$a_01_7 = {43 68 69 6c 62 6c 61 69 6e 2e 64 6c 6c } //1 Chilblain.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=2
 
}