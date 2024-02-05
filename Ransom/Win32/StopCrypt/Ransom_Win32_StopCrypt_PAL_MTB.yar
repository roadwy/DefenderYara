
rule Ransom_Win32_StopCrypt_PAL_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 10 89 45 90 01 01 8b 45 0c 31 45 90 01 01 8b 45 90 01 01 8b 4d 08 89 01 90 02 02 c9 c2 0c 00 81 00 03 35 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}