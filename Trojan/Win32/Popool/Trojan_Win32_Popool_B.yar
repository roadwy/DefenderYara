
rule Trojan_Win32_Popool_B{
	meta:
		description = "Trojan:Win32/Popool.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 38 00 00 68 65 6c 6c 6f 25 73 00 6e 6f 20 75 73 65 00 00 3a 00 00 00 68 74 74 70 00 00 00 00 30 00 00 00 68 74 74 70 73 00 00 00 6f 70 65 6e 09 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 29 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}