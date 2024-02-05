
rule Trojan_Win32_Fedcept_A{
	meta:
		description = "Trojan:Win32/Fedcept.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 3e 34 6d 66 98 66 89 02 41 8a 01 42 42 } //01 00 
		$a_01_1 = {2b f0 32 ca 88 0c 06 40 8a 08 84 c9 } //01 00 
		$a_03_2 = {46 00 52 00 65 00 64 00 90 02 06 25 00 73 00 3f 00 55 00 49 00 44 00 3d 00 25 00 73 00 26 00 57 00 49 00 4e 00 56 00 45 00 52 00 3d 00 25 00 78 00 25 00 30 00 32 00 78 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}