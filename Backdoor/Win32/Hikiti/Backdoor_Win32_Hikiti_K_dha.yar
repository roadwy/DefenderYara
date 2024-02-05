
rule Backdoor_Win32_Hikiti_K_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8c 24 24 43 2b 2b 22 13 13 13 00 } //01 00 
		$a_01_1 = {8a 25 25 42 28 28 20 1c 1c 1c 15 15 15 0e 0e 0e 05 05 05 00 } //00 00 
	condition:
		any of ($a_*)
 
}