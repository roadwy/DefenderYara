
rule Trojan_Win32_Zonsterarch_Z{
	meta:
		description = "Trojan:Win32/Zonsterarch.Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 6b 79 70 65 90 02 80 65 6c 33 32 3a 3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 90 00 } //01 00 
		$a_00_1 = {3a 3a 53 77 69 6c 28 74 20 72 31 2c 20 74 20 72 33 29 20 69 2e 73 } //00 00 
	condition:
		any of ($a_*)
 
}