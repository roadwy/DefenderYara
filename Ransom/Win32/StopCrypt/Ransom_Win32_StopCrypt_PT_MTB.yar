
rule Ransom_Win32_StopCrypt_PT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 50 50 50 50 50 ff 15 90 01 04 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 40 36 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}