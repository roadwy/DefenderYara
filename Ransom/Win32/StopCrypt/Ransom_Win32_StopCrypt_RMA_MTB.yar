
rule Ransom_Win32_StopCrypt_RMA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 c1 ee 90 01 01 03 f5 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 ff 15 90 01 04 8b 4c 24 90 01 01 33 ce 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 81 44 24 90 01 05 83 6c 24 90 01 02 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}