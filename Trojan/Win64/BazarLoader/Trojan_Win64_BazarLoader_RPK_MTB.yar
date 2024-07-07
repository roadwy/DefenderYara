
rule Trojan_Win64_BazarLoader_RPK_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {78 6c 6c 2d 74 72 61 6e 73 66 65 72 2e 78 6c 6c } //1 xll-transfer.xll
		$a_01_1 = {53 65 74 45 78 63 65 6c 31 32 45 6e 74 72 79 50 74 } //1 SetExcel12EntryPt
		$a_01_2 = {58 4c 43 61 6c 6c 56 65 72 } //1 XLCallVer
		$a_01_3 = {78 6c 41 75 74 6f 4f 70 65 6e } //1 xlAutoOpen
		$a_01_4 = {58 4c 43 61 6c 6c 33 32 2e 64 6c 6c } //1 XLCall32.dll
		$a_01_5 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //1 rundll32
		$a_01_6 = {4a 00 61 00 76 00 61 00 4f 00 62 00 6a 00 65 00 63 00 74 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 52 00 2e 00 64 00 6c 00 6c 00 } //1 JavaObjectReflectR.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}