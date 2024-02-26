
rule TrojanSpy_BAT_Bobik_SK_MTB{
	meta:
		description = "TrojanSpy:BAT/Bobik.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 08 16 08 8e 69 6f 33 00 00 0a 13 05 28 34 00 00 0a 11 05 6f 35 00 00 0a 13 06 de 0c } //02 00 
		$a_81_1 = {5c 72 65 73 6f 75 72 63 65 66 69 6c 65 68 61 68 61 2e 65 78 65 } //00 00  \resourcefilehaha.exe
	condition:
		any of ($a_*)
 
}