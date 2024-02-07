
rule TrojanDropper_Win32_Agent_SK_eml{
	meta:
		description = "TrojanDropper:Win32/Agent.SK.eml,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 4d 4d 49 43 43 4f 76 61 } //01 00  AMMICCOva
		$a_01_1 = {7a 00 61 00 73 00 41 00 53 00 } //01 00  zasAS
		$a_01_2 = {47 00 41 00 53 00 41 00 53 00 2e 00 65 00 78 00 65 00 } //00 00  GASAS.exe
	condition:
		any of ($a_*)
 
}