
rule Ransom_Win32_Basta_PE_MTB{
	meta:
		description = "Ransom:Win32/Basta.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea ?? 69 c2 ?? ?? ?? ?? 2b c8 75 ?? ff d6 8b f8 ff d6 3b c7 74 f6 8b 4d fc 8b c1 99 f7 fb 8b 45 ?? 33 55 ?? 8a 04 02 30 81 ?? ?? ?? ?? 41 89 4d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}