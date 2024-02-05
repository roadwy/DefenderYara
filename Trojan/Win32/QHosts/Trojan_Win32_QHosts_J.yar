
rule Trojan_Win32_QHosts_J{
	meta:
		description = "Trojan:Win32/QHosts.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 34 2e 31 39 35 2e 31 35 33 2e 39 34 20 61 70 69 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00 
		$a_01_1 = {33 34 2e 31 39 35 2e 31 35 33 2e 39 34 20 77 77 77 2e 67 6f 6f 67 6c 65 61 64 73 65 72 76 69 63 65 73 2e 63 6f 6d } //01 00 
		$a_03_2 = {bb 1d 00 00 73 90 01 01 8b 90 01 02 90 02 03 0f be 90 01 03 90 02 03 83 90 01 02 8b 90 01 02 90 02 03 88 90 01 03 90 02 03 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}