
rule Ransom_Win32_StopCrypt_PAV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 00 47 86 c8 61 c3 33 44 24 04 c2 04 00 81 00 90 01 01 34 ef c6 c3 55 8d 6c 24 90 01 01 81 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}