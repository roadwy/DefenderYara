
rule Backdoor_Win32_Chafesi_A{
	meta:
		description = "Backdoor:Win32/Chafesi.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 61 63 61 72 69 70 73 00 } //02 00 
		$a_01_1 = {5c 00 55 00 73 00 65 00 72 00 20 00 41 00 67 00 65 00 6e 00 74 00 5c 00 50 00 6f 00 73 00 74 00 20 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 5c 00 61 00 62 00 63 00 3a 00 00 00 } //01 00 
		$a_01_2 = {3a 00 63 00 62 00 61 00 00 00 } //01 00 
		$a_01_3 = {67 72 61 62 61 72 61 72 63 68 69 76 6f 00 } //01 00 
		$a_03_4 = {6a 68 52 ff d6 8d 85 90 01 02 ff ff 6a 6f 50 ff d6 8d 8d 90 01 02 ff ff 6a 73 51 ff d6 8d 95 90 01 02 ff ff 6a 74 52 ff d6 8d 85 90 01 02 ff ff 6a 73 90 00 } //01 00 
		$a_03_5 = {6a 38 50 ff d6 8d 8d 90 01 02 ff ff 6a 39 51 ff d6 8d 95 90 01 02 ff ff 6a 2b 52 ff d6 8d 85 90 01 02 ff ff 6a 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}