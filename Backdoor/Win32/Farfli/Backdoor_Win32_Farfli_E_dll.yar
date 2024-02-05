
rule Backdoor_Win32_Farfli_E_dll{
	meta:
		description = "Backdoor:Win32/Farfli.E!dll,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {7e 11 8a 04 32 3c 22 74 05 2c 90 01 01 88 04 32 42 3b d1 7c ef 8b c6 5e c2 04 00 90 00 } //05 00 
		$a_01_1 = {68 24 0c 0b 83 56 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}