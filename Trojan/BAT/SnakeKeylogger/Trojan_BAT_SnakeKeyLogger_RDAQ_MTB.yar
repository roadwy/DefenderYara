
rule Trojan_BAT_SnakeKeyLogger_RDAQ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 6e 64 72 65 77 73 79 20 4c 69 62 } //1 Andrewsy Lib
		$a_01_1 = {57 6f 72 64 50 72 6f 63 65 73 73 6f 72 43 68 61 6d 62 65 72 6c 69 6e } //1 WordProcessorChamberlin
		$a_01_2 = {43 68 69 6c 64 45 64 69 74 6f 72 } //1 ChildEditor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}