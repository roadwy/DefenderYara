
rule Backdoor_Win32_Escad_E_dha{
	meta:
		description = "Backdoor:Win32/Escad.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {78 56 34 12 55 55 ?? f2 78 56 34 12 [0-20] ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Backdoor_Win32_Escad_E_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {78 56 34 12 55 55 ?? f2 78 56 34 12 [0-20] ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}