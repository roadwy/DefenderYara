
rule Ransom_Win32_StopCrypt_MCK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 65 f0 00 2b df 25 90 02 04 81 6d f0 90 02 04 81 45 f0 90 02 04 8b 4d dc 8b c3 c1 e8 90 02 01 89 45 ec 8d 45 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}