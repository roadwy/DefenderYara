
rule Virus_Win32_Pavsee_gen_A{
	meta:
		description = "Virus:Win32/Pavsee.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 62 00 00 72 62 00 00 72 62 2b 00 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 48 6f 73 74 3a 20 00 00 0d 0a 00 00 2e 74 78 74 20 48 54 54 50 2f 31 2e 31 0d 0a 00 47 45 54 20 2f 00 00 00 2e 65 78 65 00 00 00 00 2e 74 6d 70 00 00 00 00 5c 00 00 00 2e 6c 6e 6b 00 00 00 00 3a 5c 00 00 2e 63 6f 6d 00 00 00 00 2a 2e 2a 00 54 45 40 00 } //01 00 
		$a_03_1 = {ff ff 66 c7 85 90 01 02 ff ff 90 01 02 66 c7 85 90 01 02 ff ff 90 01 02 66 89 b5 90 01 02 ff ff 8d bd fc 90 01 02 ff f3 ab 59 66 c7 85 90 01 02 ff ff 77 00 66 c7 85 90 01 02 ff ff 77 00 66 c7 85 90 01 02 ff ff 77 00 66 89 95 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}