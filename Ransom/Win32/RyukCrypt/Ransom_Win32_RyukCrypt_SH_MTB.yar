
rule Ransom_Win32_RyukCrypt_SH_MTB{
	meta:
		description = "Ransom:Win32/RyukCrypt.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {51 6a 00 ff 15 90 01 04 8b 15 90 01 04 a3 90 01 04 a1 90 01 04 33 f6 89 15 90 01 04 85 c0 76 3e 8b 3d 90 01 04 bb 90 01 04 8b 0d 90 01 04 8a 94 31 90 01 04 8b 0d 90 01 04 88 14 31 3d 90 01 04 75 90 01 01 6a 00 6a 00 ff d7 a1 90 01 04 89 1d 90 01 04 46 3b f0 72 90 00 } //02 00 
		$a_03_1 = {46 3b f0 72 90 01 01 68 90 01 04 68 90 01 04 ff 15 90 01 04 68 90 01 04 ff 15 90 01 04 68 90 01 04 50 ff 15 90 01 04 8b 0d 90 01 04 8d 54 24 10 52 8b 15 90 01 04 6a 40 51 52 a3 90 01 04 ff d0 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}