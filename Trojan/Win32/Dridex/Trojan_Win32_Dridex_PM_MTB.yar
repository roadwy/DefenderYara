
rule Trojan_Win32_Dridex_PM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 04 00 "
		
	strings :
		$a_00_0 = {07 52 86 e8 6c 19 4a d9 a5 df 5d db 30 b2 5e 39 ab e0 ff ae 41 f2 74 b7 b7 3e 70 1a e4 7d 50 33 bb d3 06 c8 eb e6 4a 58 a5 df 7d 27 30 e5 5e 25 } //01 00 
		$a_81_1 = {62 61 63 6b 67 72 6f 75 6e 64 2e 74 68 65 72 65 31 4d 35 31 38 66 69 72 65 } //01 00  background.there1M518fire
		$a_81_2 = {47 6f 6f 67 6c 65 66 75 63 6b 6d 65 74 68 65 61 66 74 65 72 59 4a } //01 00  GooglefuckmetheafterYJ
		$a_81_3 = {66 6f 72 74 6f 46 6f 74 68 65 72 64 46 6c 61 73 68 73 68 61 72 65 2e 33 30 55 69 6e 73 74 61 6e 63 65 43 68 72 6f 6d 65 } //01 00  fortoFotherdFlashshare.30UinstanceChrome
		$a_81_4 = {69 61 6c 6c 6f 77 73 6c 61 74 65 72 } //01 00  iallowslater
		$a_81_5 = {77 65 62 73 69 74 65 73 74 68 65 55 35 6c 61 75 6e 63 68 } //01 00  websitestheU5launch
		$a_81_6 = {70 72 6f 63 65 73 73 65 73 5a 73 65 63 75 72 69 74 79 } //00 00  processesZsecurity
	condition:
		any of ($a_*)
 
}