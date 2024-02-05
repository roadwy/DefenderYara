
rule Ransom_Win32_Genasom_GG{
	meta:
		description = "Ransom:Win32/Genasom.GG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 63 6f 64 65 72 73 6f 66 74 40 53 61 66 65 2d 6d 61 69 6c 2e 6e 65 74 } //01 00 
		$a_01_1 = {41 4c 4c 45 20 50 45 52 53 d6 4e 4c 49 43 48 45 4e 20 44 41 54 45 4e 20 56 4f 4e 20 49 48 4e 45 4e 20 57 55 52 44 45 4e 20 56 45 52 53 43 48 4c dc 53 53 45 4c 54 21 } //01 00 
		$a_01_2 = {2e 6b 73 72 } //01 00 
		$a_01_3 = {53 4f 4c 4c 54 45 20 45 55 45 52 20 55 4b 41 53 48 2d 43 4f 44 45 20 49 4e 20 4f 52 44 4e 55 4e 47 20 53 45 49 4e } //01 00 
		$a_01_4 = {75 2b 8b f8 8b d8 c1 eb 10 81 e7 00 00 ff 00 0b fb 8b d8 81 e3 00 ff 00 00 c1 e0 10 0b d8 c1 ef 08 c1 e3 08 0b fb } //00 00 
	condition:
		any of ($a_*)
 
}