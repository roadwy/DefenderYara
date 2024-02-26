
rule Backdoor_MacOS_GetShell_B_MTB{
	meta:
		description = "Backdoor:MacOS/GetShell.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {15 0f 01 00 00 00 00 1d b8 00 00 00 00 5f 5f 73 74 61 72 74 00 5f 63 6f 6d 6d 65 6e 74 00 5f 73 68 65 6c 6c 63 6f 64 } //05 00 
		$a_00_1 = {5f 5f 73 74 61 72 74 00 5f 63 6f 6d 6d 65 6e 74 00 5f 73 68 65 6c 6c 63 6f 64 65 00 5f 2e 73 74 72 00 00 00 } //01 00 
		$a_00_2 = {5f 73 68 65 6c 6c 63 6f 64 65 } //00 00  _shellcode
	condition:
		any of ($a_*)
 
}