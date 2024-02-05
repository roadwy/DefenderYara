
rule Ransom_Win32_StopCrypt_PBN_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 03 45 90 01 01 8b d7 89 45 90 01 01 8d 04 3e 50 8d 45 90 01 01 c1 ea 05 03 55 90 01 01 50 c7 05 90 01 04 b4 21 e1 c5 e8 90 02 04 8b 45 90 02 08 33 c2 29 45 90 02 06 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}