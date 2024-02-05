
rule Backdoor_Win32_Delf_RAK{
	meta:
		description = "Backdoor:Win32/Delf.RAK,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 } //01 00 
		$a_00_1 = {53 65 74 20 63 64 61 75 64 69 6f 20 64 6f 6f 72 20 6f 70 65 6e 20 77 61 69 74 } //01 00 
		$a_00_2 = {44 4f 4d 00 ff ff ff ff 04 00 00 00 46 52 45 45 } //05 00 
		$a_02_3 = {89 45 fc 33 c0 55 68 90 01 04 64 ff 30 64 89 20 ba 90 01 04 8b 45 fc e8 90 01 04 33 c9 ba 90 01 04 8b 45 fc e8 90 01 04 84 c0 74 0d ba 90 01 04 8b 45 fc e8 90 01 04 8b 45 fc e8 90 01 04 33 c0 5a 59 59 64 89 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}