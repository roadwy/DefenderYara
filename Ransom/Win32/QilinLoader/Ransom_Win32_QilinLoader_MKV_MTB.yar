
rule Ransom_Win32_QilinLoader_MKV_MTB{
	meta:
		description = "Ransom:Win32/QilinLoader.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ea 89 5c 24 4c 8b 4c 24 34 89 44 24 54 8b 44 24 24 89 74 24 50 8b 00 89 5c 24 28 89 44 24 30 0f b7 40 06 66 89 44 24 ?? 0f b7 44 24 2c 83 c1 01 83 c7 28 39 c1 0f 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}