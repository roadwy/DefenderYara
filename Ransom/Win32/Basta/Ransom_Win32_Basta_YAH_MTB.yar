
rule Ransom_Win32_Basta_YAH_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 81 c1 ?? ?? ?? ?? 33 c8 89 8e b4 00 00 00 8b 86 88 00 00 00 8b 1c 28 83 c5 04 a1 ?? ?? ?? ?? 0f af 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}