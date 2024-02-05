
rule Trojan_Win32_Cotfuser_A{
	meta:
		description = "Trojan:Win32/Cotfuser.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 0f b6 14 08 66 b9 ff 00 66 2b ca 0f 80 0d 01 00 00 ff 15 } //01 00 
		$a_01_1 = {81 f9 4d 5a 00 00 74 13 } //01 00 
		$a_00_2 = {63 00 61 00 63 00 6c 00 73 00 20 00 63 00 3a 00 5c 00 20 00 2f 00 65 00 20 00 2f 00 67 00 20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 3a 00 66 00 } //00 00 
	condition:
		any of ($a_*)
 
}