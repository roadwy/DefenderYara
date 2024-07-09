
rule Ransom_Win32_Makop_SA_MTB{
	meta:
		description = "Ransom:Win32/Makop.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea ?? 03 54 24 ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 8b 44 24 ?? d1 6c 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}