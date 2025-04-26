
rule Trojan_Win32_Tepfer_GNN_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d fc 03 c7 30 08 47 3b } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}