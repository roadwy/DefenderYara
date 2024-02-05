
rule Trojan_Win32_Gatak_DQ_dha{
	meta:
		description = "Trojan:Win32/Gatak.DQ!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 41 54 51 00 68 43 4c 42 43 54 ff 15 } //01 00 
		$a_01_1 = {31 c0 50 68 41 54 51 00 68 43 4c 42 43 54 ff 15 } //01 00 
		$a_01_2 = {6a 00 68 41 54 51 00 68 43 4c 42 43 54 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}