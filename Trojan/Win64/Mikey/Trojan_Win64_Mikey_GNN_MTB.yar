
rule Trojan_Win64_Mikey_GNN_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 ed 69 83 ?? ?? ?? ?? 50 ed 06 83 54 ec 6f 83 55 ?? 18 82 54 ec 24 fb 55 ed } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}