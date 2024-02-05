
rule Adware_Win32_Cutoart_A_MSR{
	meta:
		description = "Adware:Win32/Cutoart.A!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 6e 69 6f 6e 2e 68 61 6f 33 36 30 33 2e 63 6f 6d 2f 61 70 69 2f 64 6f 77 6e } //01 00 
		$a_01_1 = {4d 54 49 7a 4e 44 55 32 4e 7a 67 35 4d 54 49 7a 4e 44 55 32 4e 7a 67 35 4d 54 49 7a 4e 44 55 32 } //00 00 
	condition:
		any of ($a_*)
 
}