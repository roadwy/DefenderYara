
rule Ransom_Win32_Tescrypt_U{
	meta:
		description = "Ransom:Win32/Tescrypt.U,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 4f 47 55 45 5f 53 54 41 52 54 00 } //01 00 
		$a_01_1 = {52 4f 47 55 45 5f 45 4e 44 00 } //01 00 
		$a_03_2 = {0f be 00 85 c0 74 90 01 01 8b 45 90 01 01 03 45 90 01 01 0f be 00 8b 4d 90 01 01 0f af 4d 90 01 01 03 c1 8b 4d 90 01 01 03 4d 90 01 01 0f b6 09 33 c8 8b 45 90 01 01 03 45 90 01 01 88 08 8b 45 90 01 01 40 89 45 90 01 01 eb 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 2d 
	condition:
		any of ($a_*)
 
}