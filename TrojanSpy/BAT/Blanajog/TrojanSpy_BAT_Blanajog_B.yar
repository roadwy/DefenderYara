
rule TrojanSpy_BAT_Blanajog_B{
	meta:
		description = "TrojanSpy:BAT/Blanajog.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6a 4c 6f 67 67 65 72 } //1 njLogger
		$a_01_1 = {4c 61 73 74 41 56 } //1 LastAV
		$a_01_2 = {6f 00 70 00 65 00 6e 00 6b 00 6c 00 } //1 openkl
		$a_01_3 = {67 00 65 00 74 00 6c 00 6f 00 67 00 73 00 } //1 getlogs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}