
rule Trojan_Win32_Malex_GNN_MTB{
	meta:
		description = "Trojan:Win32/Malex.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 f6 44 24 08 10 75 0a 33 c0 5e } //5
		$a_01_1 = {8a 16 32 d0 88 16 46 8d 14 37 83 fa 08 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}