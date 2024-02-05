
rule Trojan_Win32_Delf_IN{
	meta:
		description = "Trojan:Win32/Delf.IN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 6e 4e 75 6f 49 45 2e 74 6d 70 90 01 09 63 6e 2e 74 6d 70 90 01 0a 63 6e 2e 65 78 65 90 00 } //01 00 
		$a_03_1 = {6d 79 69 65 90 01 06 73 65 74 75 70 2e 65 78 65 90 01 09 2e 78 7a 31 39 2e 63 6f 6d 90 00 } //01 00 
		$a_03_2 = {71 72 6e 5f 90 01 0c 6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f 90 00 } //01 00 
		$a_03_3 = {78 7a 7a 2f 90 09 10 00 25 64 90 01 02 64 6b 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}