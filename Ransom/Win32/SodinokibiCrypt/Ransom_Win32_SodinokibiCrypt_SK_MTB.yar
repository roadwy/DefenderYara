
rule Ransom_Win32_SodinokibiCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/SodinokibiCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {ff 59 57 bf 90 01 04 ff 15 90 01 04 81 3d 90 01 04 90 01 02 00 00 75 90 01 01 56 ff 15 90 01 04 4f 75 90 01 01 e8 90 01 02 ff ff 90 00 } //02 00 
		$a_02_1 = {30 04 3e 4e 0f 89 90 0a 90 00 81 6d 90 01 05 81 ad 90 01 08 81 6d 90 01 05 81 6d 90 01 05 81 6d 90 01 05 81 ad 90 01 08 81 6d 90 01 05 81 45 90 01 05 81 6d 90 01 05 81 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}