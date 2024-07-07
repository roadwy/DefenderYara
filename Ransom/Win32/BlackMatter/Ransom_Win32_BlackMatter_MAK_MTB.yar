
rule Ransom_Win32_BlackMatter_MAK_MTB{
	meta:
		description = "Ransom:Win32/BlackMatter.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 ad 66 83 f8 90 01 01 72 0a 66 83 f8 5a 90 13 80 c6 61 80 ee 61 c1 ca 90 01 01 03 d0 85 c0 75 90 00 } //1
		$a_03_1 = {0f b7 37 c1 e6 90 01 01 03 72 1c 03 f3 ad 03 c3 89 45 fc 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}