
rule Trojan_Win64_IcedID_GIL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {78 6c 6c 2d 74 72 61 6e 73 66 65 72 2e 78 6c 6c } //1 xll-transfer.xll
		$a_80_1 = {4a 65 74 42 72 61 69 6e 73 64 6f 74 4e 65 62 2e 64 6c 6c } //JetBrainsdotNeb.dll  1
		$a_80_2 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //QueryPerformanceCounter  1
		$a_01_3 = {42 6f 61 67 45 6c 70 79 44 6a 6d 71 63 78 61 } //1 BoagElpyDjmqcxa
		$a_01_4 = {45 69 6b 63 61 54 79 65 6a 6b 6a 55 6a 6c 6e 61 } //1 EikcaTyejkjUjlna
		$a_01_5 = {46 70 63 7a 78 6e 61 68 50 69 62 62 71 61 78 66 61 75 65 67 } //1 FpczxnahPibbqaxfaueg
		$a_01_6 = {4f 6d 75 6b 76 74 77 72 41 7a 70 6b 46 61 69 64 65 6f 6f 68 77 79 66 } //1 OmukvtwrAzpkFaideoohwyf
		$a_01_7 = {53 65 74 45 78 63 65 6c 31 32 45 6e 74 72 79 50 74 } //1 SetExcel12EntryPt
		$a_01_8 = {58 4c 43 61 6c 6c 56 65 72 } //1 XLCallVer
		$a_01_9 = {78 6c 41 75 74 6f 4f 70 65 6e } //1 xlAutoOpen
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}