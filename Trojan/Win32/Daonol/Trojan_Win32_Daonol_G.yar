
rule Trojan_Win32_Daonol_G{
	meta:
		description = "Trojan:Win32/Daonol.G,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 64 72 69 76 65 72 73 33 32 } //01 00 
		$a_01_1 = {77 69 6e 6d 6d 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 6e 74 69 4d 63 48 54 4e 4f 44 33 4c 49 56 45 50 61 6e 64 } //01 00 
		$a_01_3 = {5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}