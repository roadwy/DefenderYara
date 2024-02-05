
rule TrojanDropper_Win32_Small_AJS{
	meta:
		description = "TrojanDropper:Win32/Small.AJS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 53 f8 40 74 46 48 86 e4 50 56 6a 00 54 86 e4 83 2c 24 50 55 57 86 f6 50 ff 53 e4 5e 9b ff 53 f4 8b 54 24 04 86 f6 8b 04 24 6a 01 6a 00 6a 00 50 6a 00 9b 6a 00 ff d2 86 e4 03 fd 90 57 ff 53 e0 } //00 00 
	condition:
		any of ($a_*)
 
}