
rule Backdoor_Win32_Codhax_A_MSR{
	meta:
		description = "Backdoor:Win32/Codhax.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 43 6f 64 65 73 5c 56 65 72 73 69 6f 6e 32 5c 48 45 58 43 41 4c 43 5c 52 65 6c 65 61 73 65 5c 48 45 58 43 41 4c 43 2e 70 64 62 } //01 00  C:\Codes\Version2\HEXCALC\Release\HEXCALC.pdb
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {47 00 6f 00 6c 00 64 00 54 00 65 00 6d 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  GoldTemp.exe
	condition:
		any of ($a_*)
 
}