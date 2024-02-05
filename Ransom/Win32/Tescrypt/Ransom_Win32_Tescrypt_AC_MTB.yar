
rule Ransom_Win32_Tescrypt_AC_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c8 89 45 90 01 01 2b f9 25 90 01 04 8b c7 8d 4d 90 01 01 e8 90 01 04 8b 4d 90 01 01 8b c7 c1 e8 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 03 c7 50 8b 45 90 01 01 03 c3 e8 90 01 04 8b 4d 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 83 25 90 01 05 2b 75 90 01 01 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 01 04 8b 45 90 01 01 89 78 90 01 01 5f 89 30 5e 5b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}