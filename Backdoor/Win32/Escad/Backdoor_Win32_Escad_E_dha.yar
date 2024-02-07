
rule Backdoor_Win32_Escad_E_dha{
	meta:
		description = "Backdoor:Win32/Escad.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {78 56 34 12 55 55 90 01 01 f2 78 56 34 12 90 02 20 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Escad_E_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {78 56 34 12 55 55 90 01 01 f2 78 56 34 12 90 02 20 ff 15 90 00 } //00 00 
		$a_00_1 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}