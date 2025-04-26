
rule Worm_Win32_Autorun_OS{
	meta:
		description = "Worm:Win32/Autorun.OS,SIGNATURE_TYPE_PEHSTR,12 00 12 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 80 fb 5b 0f 85 b2 f4 ff ff b3 43 } //5
		$a_01_1 = {47 65 74 44 72 69 76 65 54 79 70 65 41 } //5 GetDriveTypeA
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c 00 } //5 体呆䅗䕒䉜牯慬摮䑜汥桰屩呒L
		$a_01_3 = {5c 68 65 6c 70 5c 43 53 52 53 53 2e 65 78 65 } //1 \help\CSRSS.exe
		$a_01_4 = {5c 68 65 6c 70 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \help\Autorun.inf
		$a_01_5 = {5c 73 65 63 75 72 69 74 79 5c 43 53 52 53 53 2e 65 78 65 } //1 \security\CSRSS.exe
		$a_01_6 = {5c 73 65 63 75 72 69 74 79 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \security\Autorun.inf
		$a_01_7 = {6f 70 65 6e 3d 43 53 52 53 53 2e 65 78 65 } //1 open=CSRSS.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=18
 
}