
rule TrojanSpy_Win32_Banker_ACF{
	meta:
		description = "TrojanSpy:Win32/Banker.ACF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {18 00 00 00 62 90 01 01 72 90 01 01 61 90 01 0f 6f 90 01 01 6d 90 00 } //01 00 
		$a_02_1 = {28 00 00 00 43 90 01 0f 41 90 01 01 7e 90 01 05 47 90 01 01 62 90 01 0b 6e 90 00 } //01 00 
		$a_02_2 = {50 00 00 00 5c 90 01 07 67 90 01 07 43 90 01 31 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}