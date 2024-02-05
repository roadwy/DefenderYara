
rule Trojan_Win32_GoldenSpy_A{
	meta:
		description = "Trojan:Win32/GoldenSpy.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6e 69 6e 67 7a 68 69 64 61 74 61 2e 63 6f 6d 3a 39 30 30 36 2f 73 6f 66 74 53 65 72 76 65 72 2f } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 49 44 47 5c 44 41 } //01 00 
		$a_01_2 = {6e 62 5f 61 70 70 5f 6c 6f 67 5f 6d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}