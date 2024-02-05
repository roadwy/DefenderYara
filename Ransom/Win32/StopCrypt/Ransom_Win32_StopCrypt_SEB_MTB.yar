
rule Ransom_Win32_StopCrypt_SEB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c5 33 44 24 90 01 01 33 c8 2b f9 8d 44 24 90 01 01 89 4c 24 90 01 01 89 7c 24 90 01 01 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 01 04 8b 84 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}