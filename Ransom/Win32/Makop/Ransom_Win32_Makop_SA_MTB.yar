
rule Ransom_Win32_Makop_SA_MTB{
	meta:
		description = "Ransom:Win32/Makop.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 90 01 01 03 54 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 7c 24 90 01 01 8b 44 24 90 01 01 d1 6c 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}