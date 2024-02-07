
rule Backdoor_Win32_Lianoufa_V_MTB{
	meta:
		description = "Backdoor:Win32/Lianoufa.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {8a 4c 05 fb 30 4c 05 fc 48 75 } //02 00 
		$a_00_1 = {8a 4c 05 63 30 4c 05 64 48 75 } //01 00 
		$a_81_2 = {64 6f 6e 6f 74 62 6f 74 68 65 72 6d 65 } //00 00  donotbotherme
	condition:
		any of ($a_*)
 
}