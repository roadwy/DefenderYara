
rule Trojan_Win32_BHO_DO{
	meta:
		description = "Trojan:Win32/BHO.DO,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {63 73 79 73 73 6a 74 2e 64 61 74 } //03 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 65 69 64 6f 75 31 32 33 2e 63 6e 2f 63 6f 75 6e 74 2e 61 73 70 } //02 00 
		$a_01_2 = {42 48 4f 4c 4f 43 4b 45 52 2e 42 68 6f 4c 6f 63 6b 2e 31 20 3d 20 73 20 27 42 68 6f 4c 6f 63 6b 20 43 6c 61 73 73 27 } //00 00 
	condition:
		any of ($a_*)
 
}