
rule Ransom_Win32_Basta_YAF_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c7 04 8b 46 34 0f af 5e 3c 03 c2 33 81 c0 00 00 00 35 ?? ?? ?? ?? 89 81 c0 00 00 00 a1 ?? ?? ?? ?? 8b 4e 58 8b d3 c1 ea 08 88 14 08 ff 46 58 a1 ?? ?? ?? ?? 8b 80 d8 00 00 00 2d 64 d7 03 00 31 46 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}