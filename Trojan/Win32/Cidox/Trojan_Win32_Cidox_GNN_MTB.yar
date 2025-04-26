
rule Trojan_Win32_Cidox_GNN_MTB{
	meta:
		description = "Trojan:Win32/Cidox.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 e4 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8a 00 32 45 e4 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}