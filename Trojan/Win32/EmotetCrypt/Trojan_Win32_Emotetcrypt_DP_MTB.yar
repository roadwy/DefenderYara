
rule Trojan_Win32_Emotetcrypt_DP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 ff 73 90 01 01 2b c8 6a 00 89 4c 24 90 01 01 ff d1 90 00 } //01 00 
		$a_02_1 = {8b 54 24 2c 4b 8b 4c 24 20 8b c3 25 ff 03 00 00 88 0c 10 8b 4f f8 8b 17 03 cd 03 54 24 14 8b 77 fc 85 f6 74 90 01 01 8a 02 8d 49 01 88 41 ff 8d 52 01 83 ee 01 75 90 01 01 83 c7 28 85 db 75 90 00 } //01 00 
		$a_81_2 = {72 75 73 74 5f 70 61 6e 69 63 } //01 00  rust_panic
		$a_81_3 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //01 00  RaiseException
		$a_81_4 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //01 00  Control_RunDLL
		$a_81_5 = {61 68 6e 7a 74 73 63 6b 79 6b } //01 00  ahnztsckyk
		$a_81_6 = {61 6a 6c 76 62 6e 7a 76 76 6b 77 61 62 62 69 75 } //00 00  ajlvbnzvvkwabbiu
	condition:
		any of ($a_*)
 
}