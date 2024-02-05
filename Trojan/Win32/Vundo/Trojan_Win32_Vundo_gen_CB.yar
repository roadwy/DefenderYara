
rule Trojan_Win32_Vundo_gen_CB{
	meta:
		description = "Trojan:Win32/Vundo.gen!CB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 04 83 45 fc 06 8b 45 fc ff 14 85 90 01 02 90 04 01 03 00 01 02 10 90 00 } //01 00 
		$a_03_1 = {10 ff d0 59 90 09 0a 00 89 90 01 02 90 04 01 03 4f 4e 49 79 90 01 01 68 90 01 02 90 03 01 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}