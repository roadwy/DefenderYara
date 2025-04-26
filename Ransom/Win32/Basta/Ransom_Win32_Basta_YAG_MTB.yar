
rule Ransom_Win32_Basta_YAG_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f0 01 0f af 46 74 89 46 74 8b 86 ec 00 00 00 03 c1 33 c9 09 05 ?? ?? ?? ?? 41 8b 46 78 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}