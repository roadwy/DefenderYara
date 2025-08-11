
rule Ransom_Win32_Basta_PAGY_MTB{
	meta:
		description = "Ransom:Win32/Basta.PAGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 86 8c 00 00 00 88 0c 02 ff 05 ?? ?? ?? ?? 8b 46 58 8b 8e 8c 00 00 00 88 1c 01 ff 46 58 a1 ?? ?? ?? ?? 8b 8e e0 00 00 00 2b 88 cc } //2
		$a_03_1 = {89 86 c0 00 00 00 a1 ?? ?? ?? ?? 8b 8e 8c 00 00 00 88 14 08 8b d3 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}