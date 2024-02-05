
rule Ransom_Win32_StopCrypt_SQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 c7 05 90 01 08 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}