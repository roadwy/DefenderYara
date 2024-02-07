
rule Backdoor_Win32_Hikiti_I_dha{
	meta:
		description = "Backdoor:Win32/Hikiti.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 4c 61 75 6e 63 68 } //02 00 
		$a_02_1 = {25 00 73 00 25 00 64 00 2e 00 64 00 61 00 74 00 90 02 40 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 90 02 20 43 00 61 00 6e 00 27 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 73 00 68 00 65 00 6c 00 6c 00 90 00 } //01 00 
		$a_00_2 = {69 6e 66 6f 2e 61 73 70 } //00 00  info.asp
		$a_00_3 = {80 10 00 00 } //38 32 
	condition:
		any of ($a_*)
 
}