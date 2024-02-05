
rule Trojan_Win32_Emotetcrypt_DA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 8b 45 90 01 01 8b 48 90 01 01 51 8b 55 90 01 01 8b 42 90 01 01 50 ff 15 90 00 } //01 00 
		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } //01 00 
		$a_00_2 = {83 c4 0c 8b 45 e4 83 c0 28 89 45 e4 eb } //01 00 
		$a_81_3 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //01 00 
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_81_5 = {52 61 69 73 65 45 78 63 65 70 74 69 6f 6e } //01 00 
		$a_81_6 = {69 6e 66 6c 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}