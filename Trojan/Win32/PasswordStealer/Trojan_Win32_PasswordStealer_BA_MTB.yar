
rule Trojan_Win32_PasswordStealer_BA_MTB{
	meta:
		description = "Trojan:Win32/PasswordStealer.BA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 46 69 6c 65 73 5c 5f 41 6c 6c 50 61 73 73 77 6f 72 64 73 5f 6c 69 73 74 2e 74 78 74 } //01 00 
		$a_01_1 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //01 00 
		$a_01_2 = {6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}