
rule Ransom_Win32_StopCrypt_PAJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 68 90 02 04 ff 90 02 06 83 65 90 02 02 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 8b 4d 08 89 01 c9 c2 90 02 02 81 00 03 35 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}