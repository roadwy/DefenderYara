
rule Backdoor_Win32_Poison_AC{
	meta:
		description = "Backdoor:Win32/Poison.AC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c4 c1 1d 00 d8 11 40 00 5c 13 40 00 6e 10 40 00 74 10 40 00 14 14 40 00 50 13 40 00 84 1e 40 00 2c 14 40 00 5c 1c 40 00 98 1e 40 00 7a 10 40 00 74 00 73 00 24 36 40 00 ba 24 36 40 00 b9 aa 10 } //01 00 
		$a_00_1 = {62 00 6f 00 6e 00 69 00 62 00 6f 00 6e 00 } //00 00  bonibon
	condition:
		any of ($a_*)
 
}