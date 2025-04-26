
rule Trojan_Win32_ICLoader_GNN_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f0 03 f8 ff 24 95 ?? ?? ?? ?? 8b ff 30 3b 63 00 38 3b 63 ?? 48 3b 63 ?? 5c 3b 63 00 8b 45 ?? 5e 5f c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_ICLoader_GNN_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 01 58 c9 c3 33 c0 c9 c3 68 a4 d3 89 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 68 88 d3 89 00 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 6a 00 ff d0 c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}