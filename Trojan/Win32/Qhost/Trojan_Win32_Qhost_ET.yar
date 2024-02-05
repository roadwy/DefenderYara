
rule Trojan_Win32_Qhost_ET{
	meta:
		description = "Trojan:Win32/Qhost.ET,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 } //01 00 
		$a_01_1 = {36 39 2e 31 36 33 2e 34 30 2e 31 31 31 20 20 20 77 77 77 2e 70 72 6f 76 69 6e 63 69 61 6c 2e 63 6f 6d 0a 00 } //01 00 
		$a_01_2 = {36 39 2e 31 36 33 2e 34 30 2e 31 31 31 20 20 20 68 74 74 70 3a 2f 2f 70 72 6f 76 69 6e 63 69 61 6c 2e 63 6f 6d 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}