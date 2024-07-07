
rule Ransom_Win32_StopCrypt_FUT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.FUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 56 56 ff 15 90 01 04 8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 8d 4d fc e8 90 01 04 8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 90 01 04 03 45 e4 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}