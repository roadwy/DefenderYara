
rule Ransom_Win32_StopCrypt_RV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 c0 90 01 01 89 45 90 01 01 83 6d 90 01 02 8a 4d 90 01 01 30 0c 1e 83 ff 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}