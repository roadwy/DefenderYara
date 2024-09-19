
rule TrojanSpy_BAT_PhemedroneStealer_SK_MTB{
	meta:
		description = "TrojanSpy:BAT/PhemedroneStealer.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 03 00 fe 0c 03 00 61 d1 fe 0e 04 00 fe 0c 01 00 fe 0c 04 00 } //2
		$a_81_1 = {73 79 73 74 65 6d 2e 65 78 65 } //2 system.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}