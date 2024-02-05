
rule Ransom_Win32_StopCrypt_ROC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.ROC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 8d 4d f8 e8 90 01 04 8b 45 d4 01 45 f8 8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 dc 33 d0 31 55 f8 2b 7d f8 89 7d e8 8b 45 e4 29 45 f4 ff 4d ec 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}