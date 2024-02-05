
rule Ransom_Win32_StopCrypt_SE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d 90 01 01 c1 e8 90 01 01 03 45 90 01 01 33 ce 33 c1 89 4d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 05 90 00 } //01 00 
		$a_03_1 = {8b 45 0c 83 6d 90 01 03 01 45 90 01 01 83 6d 90 01 02 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}