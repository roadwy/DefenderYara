
rule Trojan_Win32_Smokeloader_GNN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b d6 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}