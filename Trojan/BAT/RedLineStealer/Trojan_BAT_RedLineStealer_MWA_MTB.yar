
rule Trojan_BAT_RedLineStealer_MWA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 76 73 64 76 64 73 73 64 } //01 00  bvsdvdssd
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_5 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_7 = {44 65 62 75 67 67 65 72 } //01 00  Debugger
		$a_01_8 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_01_9 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}