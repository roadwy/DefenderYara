
rule Trojan_Win32_Ekstak_GNN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e } //5
		$a_03_1 = {32 c8 56 88 0d ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 80 c9 08 8b b4 24 ?? ?? ?? ?? c0 e9 03 81 e1 ?? ?? ?? ?? 6a 11 89 4c 24 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}