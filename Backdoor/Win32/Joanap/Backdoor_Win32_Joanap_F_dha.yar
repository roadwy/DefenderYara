
rule Backdoor_Win32_Joanap_F_dha{
	meta:
		description = "Backdoor:Win32/Joanap.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 73 5c 25 73 90 02 10 64 76 70 69 2e 64 6e 61 90 02 0a 25 73 90 02 0a 2e 64 6c 6c 90 00 } //01 00 
		$a_02_1 = {64 65 6c 20 2f 61 20 22 25 73 22 90 02 10 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}