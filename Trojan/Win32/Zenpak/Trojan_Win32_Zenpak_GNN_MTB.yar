
rule Trojan_Win32_Zenpak_GNN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 c2 89 e0 50 8f 05 ?? ?? ?? ?? 42 48 eb ?? 4a 83 c2 ?? 83 f0 ?? 83 c0 ?? 89 d8 50 8f 05 ?? ?? ?? ?? 83 f0 ?? b8 ?? ?? ?? ?? 31 35 ?? ?? ?? ?? 89 e8 50 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}