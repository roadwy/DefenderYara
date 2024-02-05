
rule Backdoor_Win32_Evelter_A_MSR{
	meta:
		description = "Backdoor:Win32/Evelter.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 44 65 76 65 6c 5c 57 69 6e 48 65 78 43 61 6c 63 2d 6d 61 73 74 65 72 5c 52 65 6c 65 61 73 65 5c 68 65 78 63 61 6c 63 2e 70 64 62 } //01 00 
		$a_01_1 = {2f 4f 69 4a 41 41 41 41 59 49 6e 6c 4d 64 4a 6b 69 31 49 77 69 31 49 4d 69 31 49 55 69 33 49 6f 44 37 64 4b 4a 6a 48 2f 4d 63 43 73 50 47 46 38 41 69 77 67 77 63 38 4e 41 63 66 69 38 46 4a } //00 00 
	condition:
		any of ($a_*)
 
}