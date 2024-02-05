
rule Ransom_Win32_StopCrypt_PQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 33 44 24 04 89 01 c2 04 00 33 44 24 04 c2 04 00 81 00 90 01 01 36 ef c6 c3 01 08 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}