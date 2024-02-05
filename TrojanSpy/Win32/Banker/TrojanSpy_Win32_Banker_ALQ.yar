
rule TrojanSpy_Win32_Banker_ALQ{
	meta:
		description = "TrojanSpy:Win32/Banker.ALQ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 72 00 74 00 2e 00 66 00 75 00 63 00 6b 00 5c 00 4e 00 6f 00 76 00 6f 00 5c 00 62 00 72 00 74 00 24 00 66 00 63 00 6b 00 } //01 00 
		$a_01_1 = {74 6d 52 65 63 6f 6e 65 63 74 61 54 69 6d 65 72 } //01 00 
		$a_01_2 = {43 61 73 61 46 61 6b 65 } //01 00 
		$a_01_3 = {54 66 45 73 70 65 6c 68 6f } //00 00 
	condition:
		any of ($a_*)
 
}