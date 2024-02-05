
rule TrojanDropper_Win32_Agent_FU{
	meta:
		description = "TrojanDropper:Win32/Agent.FU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 65 6d 70 56 69 64 69 6f 2e 62 61 74 } //01 00 
		$a_02_1 = {59 59 53 53 6a 02 53 53 8d 90 01 05 68 00 00 00 c0 51 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}