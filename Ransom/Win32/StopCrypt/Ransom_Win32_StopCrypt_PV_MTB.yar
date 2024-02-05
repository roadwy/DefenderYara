
rule Ransom_Win32_StopCrypt_PV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 44 24 04 c2 04 00 81 00 40 36 ef c6 c3 55 8b ec 81 ec 28 0c 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}