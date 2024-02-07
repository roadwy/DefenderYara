
rule Trojan_Win32_Startpage_MV{
	meta:
		description = "Trojan:Win32/Startpage.MV,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 57 59 2e 50 72 6f 74 65 63 74 65 64 2e 4e 6f 77 2e 00 } //02 00 
		$a_03_1 = {4e 65 77 20 57 69 6e 64 6f 77 73 5c 41 6c 6c 6f 77 5c 2a 2e 90 02 20 2e 63 63 90 00 } //01 00 
		$a_01_2 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 } //01 00 
		$a_01_3 = {4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 00 } //00 00  慍湩卜慴瑲倠条e
	condition:
		any of ($a_*)
 
}