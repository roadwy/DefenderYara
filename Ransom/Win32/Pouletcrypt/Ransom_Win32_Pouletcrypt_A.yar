
rule Ransom_Win32_Pouletcrypt_A{
	meta:
		description = "Ransom:Win32/Pouletcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 6f 66 74 77 61 72 65 00 00 00 00 ff ff ff ff 90 01 01 00 00 00 90 02 10 00 00 ff ff ff ff 90 01 01 00 00 00 52 61 7a 64 31 90 02 08 00 00 ff ff ff ff 90 00 } //02 00 
		$a_02_1 = {b9 01 00 00 00 e8 90 01 03 ff ff 0d 90 01 03 00 8b 90 01 01 8b 15 90 01 03 00 80 7c 10 ff 21 74 d6 90 02 30 85 c0 7e 17 ba 01 00 00 00 8b 0d 90 01 03 00 80 7c 11 ff 2f 75 01 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}