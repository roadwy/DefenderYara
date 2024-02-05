
rule Trojan_WinNT_Diskhide_A{
	meta:
		description = "Trojan:WinNT/Diskhide.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 69 64 65 5f 73 65 63 74 6f 72 } //01 00 
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 30 00 5c 00 44 00 52 00 30 00 } //01 00 
		$a_02_2 = {3d 50 00 07 00 74 90 01 01 3d 04 0c 2d 00 74 90 01 01 3d a0 00 07 00 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}