
rule Ransom_Win32_StopCrypt_MGK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2 } //01 00 
		$a_01_1 = {55 8b ec 8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a 5d c2 } //00 00 
	condition:
		any of ($a_*)
 
}