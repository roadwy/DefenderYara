
rule Ransom_Win32_StopCrypt_SAK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 8d 4c 24 90 01 01 e8 90 01 04 01 7c 24 90 01 01 89 6c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 02 01 44 24 90 01 01 8b 44 24 90 00 } //1
		$a_03_1 = {8b c6 d3 e8 8b 4c 24 90 01 01 31 4c 24 90 01 01 03 c3 81 3d 90 01 08 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}