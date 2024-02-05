
rule TrojanProxy_Win32_Treizt_A{
	meta:
		description = "TrojanProxy:Win32/Treizt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 63 6f 6e 66 69 67 2e 73 74 72 65 61 6d 00 } //01 00 
		$a_00_1 = {73 72 63 5f 68 74 74 70 5f 70 6f 72 74 } //01 00 
		$a_03_2 = {6a 04 8d 4d 90 01 01 51 68 80 00 00 00 68 ff ff 00 00 50 ff 15 90 01 04 8b 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}