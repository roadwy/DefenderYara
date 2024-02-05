
rule Trojan_Win32_Crastic_D{
	meta:
		description = "Trojan:Win32/Crastic.D,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 52 75 6e 64 6c 6c 2e 64 6c 6c 00 52 75 6e 64 6c 6c 00 } //0a 00 
		$a_01_1 = {00 52 75 6e 64 6c 6c 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 53 00 } //0b 00 
		$a_00_2 = {00 63 73 72 73 73 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 4d 00 } //02 00 
		$a_03_3 = {8b ff 8a 88 90 01 04 30 88 90 01 04 48 75 f1 33 c9 83 f8 04 90 09 37 00 c7 05 90 01 08 c7 05 90 01 08 c7 05 90 00 } //00 00 
		$a_00_4 = {7e 15 00 00 d6 07 6d c4 c7 17 f5 } //28 5d 
	condition:
		any of ($a_*)
 
}