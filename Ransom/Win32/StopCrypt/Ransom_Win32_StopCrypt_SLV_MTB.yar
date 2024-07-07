
rule Ransom_Win32_StopCrypt_SLV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 44 24 10 89 2d 90 01 04 89 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 81 c3 90 01 04 ff 4c 24 90 01 01 89 5c 24 90 00 } //1
		$a_03_1 = {89 44 24 18 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 c1 e8 90 01 01 89 44 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 8b 44 24 90 01 01 01 44 24 90 01 01 8b 54 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}