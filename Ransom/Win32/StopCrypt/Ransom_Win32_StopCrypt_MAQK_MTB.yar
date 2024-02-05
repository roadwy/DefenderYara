
rule Ransom_Win32_StopCrypt_MAQK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MAQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 d3 ee 89 45 f0 03 75 d8 33 f0 2b fe 25 90 02 04 8b c7 8d 4d f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}