
rule Ransom_Win32_Basta_MVK_MTB{
	meta:
		description = "Ransom:Win32/Basta.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 35 02 14 03 00 c1 ea 18 89 86 c0 00 00 00 a1 ?? ?? ?? ?? 8b 8e 8c 00 00 00 88 14 08 8b d3 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 9c 28 fc ff c1 ea 10 31 46 50 8b 4e 50 a1 ?? ?? ?? ?? 81 f1 02 7c 15 00 01 88 f4 00 00 00 a1 ?? ?? ?? ?? 8b 8e 8c 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}