
rule Trojan_Win32_Audhi_B{
	meta:
		description = "Trojan:Win32/Audhi.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 0b 44 72 69 76 65 72 50 72 6f 63 00 68 90 01 03 10 ff 35 90 01 03 10 e8 90 01 04 a3 90 01 03 10 eb 0b 90 00 } //01 00 
		$a_02_1 = {eb 0b 61 75 78 4d 65 73 73 61 67 65 00 68 90 01 03 10 ff 35 90 01 03 10 e8 90 00 } //01 00 
		$a_00_2 = {25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 77 64 6d 61 75 64 2e 64 72 76 } //00 00 
	condition:
		any of ($a_*)
 
}