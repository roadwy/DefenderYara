
rule Trojan_Win32_Redline_GNN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 33 c0 80 2f 90 01 01 80 07 90 01 01 47 e2 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}