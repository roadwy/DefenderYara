
rule Trojan_Win32_Godin_A{
	meta:
		description = "Trojan:Win32/Godin.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 25 73 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 22 } //01 00  Content-Disposition: form-data; name="%s"; filename="%s"
		$a_01_1 = {49 50 48 4f 4e 45 38 2e 35 28 68 6f 73 74 3a 25 73 2c 69 70 3a 25 73 29 00 } //01 00 
		$a_01_2 = {25 73 5c 46 58 53 53 54 2e 44 4c 4c 00 } //01 00 
		$a_01_3 = {61 20 64 69 6e 67 6f 27 73 20 67 6f 74 20 6d 79 20 62 61 62 79 } //00 00  a dingo's got my baby
	condition:
		any of ($a_*)
 
}