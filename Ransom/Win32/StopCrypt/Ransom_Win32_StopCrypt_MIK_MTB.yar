
rule Ransom_Win32_StopCrypt_MIK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc 90 02 04 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 33 08 8b 55 08 89 0a 8b e5 5d c2 90 00 } //01 00 
		$a_03_1 = {55 8b ec 51 c7 45 fc 90 02 04 8b 45 0c 01 45 fc 8b 45 08 8b 08 33 4d fc 8b 55 08 89 0a 8b e5 5d c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}