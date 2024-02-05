
rule Ransom_Win32_StopCrypt_MDK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2 } //01 00 
		$a_03_1 = {55 8b ec 51 c7 45 fc 90 02 04 8b 45 0c 8b 4d fc d3 e0 8b 4d 08 89 01 8b e5 5d c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}