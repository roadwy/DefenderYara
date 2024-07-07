
rule Ransom_Win32_BlackMatter_PA_MTB{
	meta:
		description = "Ransom:Win32/BlackMatter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 ad 66 85 c0 75 90 01 01 66 b8 90 01 02 66 ab b8 90 01 04 35 f8 9f 01 17 ab b8 90 01 04 35 f8 9f 01 17 ab b8 90 01 04 35 f8 9f 01 17 ab b8 90 01 04 35 f8 9f 01 17 ab 66 33 c0 66 ab eb 90 01 01 66 ab eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}