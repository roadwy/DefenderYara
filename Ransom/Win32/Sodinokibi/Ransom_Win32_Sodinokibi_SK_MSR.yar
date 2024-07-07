
rule Ransom_Win32_Sodinokibi_SK_MSR{
	meta:
		description = "Ransom:Win32/Sodinokibi.SK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 8b d0 d3 e2 8b c8 c1 e9 05 03 4d d8 03 55 dc 89 35 90 01 03 00 33 d1 8b 4d f0 03 c8 33 d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}