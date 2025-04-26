
rule Trojan_Win32_Dridex_EDS_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 12 00 0a 00 00 "
		
	strings :
		$a_80_0 = {79 31 38 39 31 74 68 65 57 61 73 73 65 72 76 65 64 6d 34 } //y1891theWasservedm4  2
		$a_80_1 = {48 65 32 47 6f 6f 67 6c 65 42 39 78 } //He2GoogleB9x  2
		$a_80_2 = {74 61 72 74 69 6e 67 50 6c 75 67 69 6e 5a 32 30 31 35 } //tartingPluginZ2015  2
		$a_80_3 = {52 74 70 6c 44 74 70 6d 69 6d 72 36 37 } //RtplDtpmimr67  2
		$a_80_4 = {74 74 74 74 33 32 } //tttt32  2
		$a_80_5 = {46 54 42 55 50 2e 70 64 62 } //FTBUP.pdb  2
		$a_80_6 = {47 67 6f 6c 66 65 72 41 42 63 6f 70 79 76 65 72 73 69 6f 6e 74 6f 70 61 73 73 76 69 64 65 6f } //GgolferABcopyversiontopassvideo  2
		$a_80_7 = {49 6e 61 6e 64 43 68 72 6f 6d 65 43 62 65 68 61 76 65 6d 6e 75 6d 62 65 72 76 63 6f 6e 73 74 69 74 75 65 6e 63 79 2e 35 } //InandChromeCbehavemnumbervconstituency.5  2
		$a_80_8 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  2
		$a_80_9 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2) >=18
 
}