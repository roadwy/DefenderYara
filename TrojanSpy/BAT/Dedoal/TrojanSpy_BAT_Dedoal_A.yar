
rule TrojanSpy_BAT_Dedoal_A{
	meta:
		description = "TrojanSpy:BAT/Dedoal.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 6e 69 74 6f 72 65 57 45 42 } //1 MonitoreWEB
		$a_01_1 = {53 6d 61 72 74 49 72 63 34 6e 65 74 57 45 42 } //1 SmartIrc4netWEB
		$a_01_2 = {44 6f 77 6e 41 6c 6c } //1 DownAll
		$a_01_3 = {52 65 73 74 61 72 74 61 46 6f 72 55 41 43 } //1 RestartaForUAC
		$a_01_4 = {44 65 74 65 63 74 41 56 } //1 DetectAV
		$a_01_5 = {47 42 45 78 69 73 74 73 } //1 GBExists
		$a_01_6 = {44 65 74 65 63 74 41 6e 64 43 6c 65 61 6e } //1 DetectAndClean
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}