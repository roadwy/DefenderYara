
rule TrojanProxy_Win32_Whirep_gen_B{
	meta:
		description = "TrojanProxy:Win32/Whirep.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 19 f6 45 fc 01 74 03 80 c3 f8 f6 45 fc 02 74 02 b3 4c f6 45 fc 04 74 02 b3 50 8a c3 } //01 00 
		$a_01_1 = {c7 45 fc 0a 00 00 00 c6 06 05 c6 46 03 01 } //02 00 
		$a_01_2 = {e8 0d 00 00 00 5c 73 79 73 72 65 73 74 2e 73 79 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}