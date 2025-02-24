
rule Trojan_Win32_ICLoader_GNN_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f0 03 f8 ff 24 95 ?? ?? ?? ?? 8b ff 30 3b 63 00 38 3b 63 ?? 48 3b 63 ?? 5c 3b 63 00 8b 45 ?? 5e 5f c9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}