
rule Ransom_Win32_LockbitCrypt_SV_MTB{
	meta:
		description = "Ransom:Win32/LockbitCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 10 00 00 8b 85 90 01 04 ff 70 90 01 01 6a 00 ff 55 90 01 01 89 45 90 00 } //02 00 
		$a_03_1 = {eb 03 c2 0c 00 55 8b ec 81 ec 90 01 04 c7 45 90 01 05 c7 45 90 01 05 8d 85 90 01 04 50 8d 45 90 01 01 50 8d 45 90 01 01 50 e8 90 01 04 83 c4 90 01 01 e8 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}