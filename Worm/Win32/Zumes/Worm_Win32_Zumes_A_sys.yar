
rule Worm_Win32_Zumes_A_sys{
	meta:
		description = "Worm:Win32/Zumes.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 42 9c 00 00 50 6a 44 57 ff 15 90 01 04 3b c3 0f 8c 90 00 } //01 00 
		$a_00_1 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 53 00 68 00 61 00 72 00 65 00 64 00 45 00 76 00 65 00 6e 00 74 00 55 00 70 00 } //01 00  \BaseNamedObjects\SharedEventUp
		$a_00_2 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 53 00 68 00 61 00 72 00 65 00 64 00 45 00 76 00 65 00 6e 00 74 00 44 00 6f 00 77 00 6e 00 } //01 00  \BaseNamedObjects\SharedEventDown
		$a_00_3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 73 00 } //00 00  \DosDevices\Ms
	condition:
		any of ($a_*)
 
}