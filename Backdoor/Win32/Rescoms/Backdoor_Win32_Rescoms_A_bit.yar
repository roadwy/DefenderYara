
rule Backdoor_Win32_Rescoms_A_bit{
	meta:
		description = "Backdoor:Win32/Rescoms.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a } //01 00  Remcos_Mutex_Inj
		$a_80_1 = {45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 } //EnableLUA /t REG_DWORD /d 0  01 00 
		$a_01_2 = {42 72 65 61 6b 69 6e 67 53 65 63 75 72 69 74 79 20 52 41 54 } //00 00  BreakingSecurity RAT
	condition:
		any of ($a_*)
 
}