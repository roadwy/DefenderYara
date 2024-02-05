
rule Ransom_Win32_StopCrypt_SLS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ca c1 e9 90 01 01 03 4d 90 01 01 8b da c1 e3 90 01 01 03 5d 90 01 01 8d 04 16 33 cb 33 c8 89 45 90 01 01 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 00 } //01 00 
		$a_03_1 = {8b 45 0c 01 45 90 01 01 83 6d fc 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}