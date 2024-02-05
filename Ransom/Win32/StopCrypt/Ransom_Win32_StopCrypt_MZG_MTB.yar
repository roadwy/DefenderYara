
rule Ransom_Win32_StopCrypt_MZG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 45 fc 8b 45 fc 8b 4d 08 89 01 5e c9 c2 90 02 02 33 44 24 04 c2 90 02 02 81 00 90 02 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}