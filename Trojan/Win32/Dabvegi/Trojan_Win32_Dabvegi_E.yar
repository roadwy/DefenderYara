
rule Trojan_Win32_Dabvegi_E{
	meta:
		description = "Trojan:Win32/Dabvegi.E,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 4e 65 78 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 } //0a 00 
		$a_00_1 = {55 52 4c 53 74 61 72 74 73 57 69 74 68 } //0a 00 
		$a_02_2 = {43 55 52 4c 48 69 73 74 6f 72 69 61 90 02 04 55 52 4c 48 69 73 74 6f 72 69 61 49 74 65 6d 90 02 04 52 57 4d 90 02 04 43 72 54 78 74 90 00 } //01 00 
		$a_00_3 = {2d 00 5b 00 38 00 38 00 5d 00 2d 00 } //00 00 
	condition:
		any of ($a_*)
 
}