
rule Ransom_Win32_Basta_YAD_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af da 8b d3 c1 ea 10 88 14 01 8b d3 ff 46 48 a1 ?? ?? ?? ?? c1 ea 08 8b 48 48 a1 ?? ?? ?? ?? 88 14 08 a1 ?? ?? ?? ?? ff 40 48 8b 4e 48 8b 86 9c 00 00 00 88 1c 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}