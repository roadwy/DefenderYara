
rule Virus_Win32_Inbind_A{
	meta:
		description = "Virus:Win32/Inbind.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7c 24 08 55 81 18 55 0f 94 c3 } //01 00 
		$a_01_1 = {2b 7c 24 0c 83 ef 08 8b c7 99 81 e2 ff 03 00 00 03 c2 c1 f8 0a 85 c0 7e } //01 00 
		$a_00_2 = {00 69 6e 66 65 63 74 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}