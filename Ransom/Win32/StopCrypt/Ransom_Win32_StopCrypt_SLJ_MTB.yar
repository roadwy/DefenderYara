
rule Ransom_Win32_StopCrypt_SLJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 20 d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 33 54 24 90 01 01 8d 4c 24 90 01 01 89 54 24 90 00 } //1
		$a_03_1 = {8b 44 24 2c c1 e8 05 89 44 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 8b 44 24 90 01 01 01 44 24 90 01 01 33 74 24 90 01 01 31 74 24 90 01 01 83 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}