
rule Trojan_Win32_Urelas_E{
	meta:
		description = "Trojan:Win32/Urelas.E,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {a5 a5 a5 66 a5 81 bd ec fb ff ff 4d 53 4d 50 89 0d f0 43 41 00 75 35 } //05 00 
		$a_01_1 = {75 04 33 c0 eb 45 81 38 4d 53 4d 50 75 f4 } //01 00 
		$a_01_2 = {67 00 6f 00 6c 00 66 00 73 00 65 00 74 00 2e 00 69 00 6e 00 69 00 00 00 } //01 00 
		$a_01_3 = {4d 00 6b 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00 } //00 00 
		$a_00_4 = {5d 04 00 00 29 } //fd 02 
	condition:
		any of ($a_*)
 
}