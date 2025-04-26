
rule Ransom_Win32_StopCrypt_LID_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.LID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 44 24 2c 8d 34 0b c1 e9 05 83 3d ?? ?? ?? ?? 1b 89 44 24 14 8b e9 75 0a ff 15 ?? ?? ?? ?? 8b 44 24 14 03 6c 24 20 c7 05 ?? ?? ?? ?? 00 00 00 00 33 ee 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}