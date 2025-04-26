
rule Trojan_Win32_Ditul_B{
	meta:
		description = "Trojan:Win32/Ditul.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 04 50 e8 ?? ?? 00 00 83 c4 04 80 38 00 8b c8 74 0e 8a 54 24 08 30 11 83 c1 01 80 39 00 75 f6 c3 } //1
		$a_01_1 = {46 60 78 45 61 71 66 6d 44 66 7b 77 71 67 67 50 71 76 61 73 5d 7a 72 7b 66 79 75 60 7d 7b 7a } //1 F`xEaqfmDf{wqggPqvas]zr{fyu`}{z
		$a_01_2 = {4b 55 76 64 72 59 76 7a 72 73 58 75 7d 72 74 63 64 4b 54 72 7b 5e 79 53 65 61 5a 76 67 } //1 KUvdrYvzrsXu}rtcdKTr{^ySeaZvg
		$a_01_3 = {46 60 78 50 71 67 60 7b 66 6d 45 61 71 66 6d 50 71 76 61 73 56 61 72 72 71 66 } //1 F`xPqg`{fmEaqfmPqvasVarrqf
		$a_01_4 = {4b 55 76 64 72 59 76 7a 72 73 58 75 7d 72 74 63 64 4b 54 72 7b 44 40 5e 59 5d } //1 KUvdrYvzrsXu}rtcdKTr{D@^Y]
		$a_01_5 = {46 60 78 57 66 71 75 60 71 45 61 71 66 6d 50 71 76 61 73 56 61 72 72 71 66 } //1 F`xWfqu`qEaqfmPqvasVarrqf
		$a_01_6 = {4e 63 45 61 71 66 6d 5d 7a 72 7b 66 79 75 60 7d 7b 7a 44 66 7b 77 71 67 67 } //1 NcEaqfm]zr{fyu`}{zDf{wqgg
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}