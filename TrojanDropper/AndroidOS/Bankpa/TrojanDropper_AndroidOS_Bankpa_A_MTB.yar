
rule TrojanDropper_AndroidOS_Bankpa_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Bankpa.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 61 70 6b 70 61 63 6b 65 72 2f 41 70 6b 50 61 63 6b 65 72 41 70 70 6c 69 63 61 74 69 6f 6e 3b } //01 00  Lapkpacker/ApkPackerApplication;
		$a_00_1 = {64 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 } //01 00  debugger detected
		$a_00_2 = {41 6e 74 69 45 6d 75 6c 61 74 6f 72 } //01 00  AntiEmulator
		$a_00_3 = {49 6e 74 65 67 72 69 74 79 43 68 65 63 6b } //00 00  IntegrityCheck
	condition:
		any of ($a_*)
 
}