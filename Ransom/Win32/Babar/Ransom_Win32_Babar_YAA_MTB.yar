
rule Ransom_Win32_Babar_YAA_MTB{
	meta:
		description = "Ransom:Win32/Babar.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af dd c1 c3 05 89 4c 24 ?? 8a ca d3 ce 8a cb 33 f3 d3 cf 33 fa 8b cf 8b d5 8b ee } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}