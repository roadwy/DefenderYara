
rule Ransom_Win32_BlackCat_SS_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.SS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d3 89 c8 31 d2 f7 f6 8b 45 f0 0f b6 04 10 89 da 30 04 0b 41 39 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}