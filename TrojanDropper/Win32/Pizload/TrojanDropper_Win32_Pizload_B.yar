
rule TrojanDropper_Win32_Pizload_B{
	meta:
		description = "TrojanDropper:Win32/Pizload.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6b 6e 78 6c 20 25 73 20 25 73 } //01 00 
		$a_01_1 = {52 61 76 54 61 73 6b 2e 65 78 65 00 52 61 76 4d } //01 00 
		$a_01_2 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //01 00 
		$a_01_3 = {77 75 61 75 63 6c 74 2e 65 78 65 00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}