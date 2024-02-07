
rule Trojan_Win32_Cudolkus_A{
	meta:
		description = "Trojan:Win32/Cudolkus.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d f6 03 00 00 76 90 01 01 57 68 90 02 0d 83 fe 0d 75 90 00 } //01 00 
		$a_01_1 = {6b 65 79 73 3a 20 25 73 } //01 00  keys: %s
		$a_01_2 = {77 69 6e 6b 2e 6c 6f 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}