
rule Trojan_Win32_Nuwar_A{
	meta:
		description = "Trojan:Win32/Nuwar.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {70 6f 6c 75 74 90 01 3d 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 90 01 04 4c 6f 61 64 4c 69 62 72 61 72 79 41 90 01 04 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 90 01 02 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 00 00 00 00 00 00 90 02 50 6d 6d 6d 2e 64 6c 5f 00 6a 61 75 64 00 70 6f 6c 75 74 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}