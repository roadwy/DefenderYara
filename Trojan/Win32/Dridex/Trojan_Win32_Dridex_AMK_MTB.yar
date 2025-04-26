
rule Trojan_Win32_Dridex_AMK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 08 00 00 "
		
	strings :
		$a_80_0 = {4c 6f 78 6d 74 59 74 } //LoxmtYt  5
		$a_80_1 = {46 47 45 52 4e 2e 70 64 62 } //FGERN.pdb  4
		$a_80_2 = {70 72 6f 76 69 64 65 73 62 6f 78 33 66 6f 72 61 } //providesbox3fora  3
		$a_80_3 = {48 65 32 47 6f 6f 67 6c 65 42 39 78 } //He2GoogleB9x  3
		$a_80_4 = {79 31 38 39 31 74 68 65 57 61 73 73 65 72 76 65 64 6d 34 } //y1891theWasservedm4  3
		$a_80_5 = {38 46 61 63 65 62 6f 6f 6b 2c 73 57 73 } //8Facebook,sWs  3
		$a_80_6 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 69 73 74 69 63 73 } //RasGetConnectionStatistics  3
		$a_80_7 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  3
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*4+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=27
 
}