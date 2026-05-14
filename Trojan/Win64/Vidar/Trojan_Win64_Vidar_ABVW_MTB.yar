
rule Trojan_Win64_Vidar_ABVW_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ABVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 33 e1 41 c1 cc ?? 41 03 c4 03 d8 44 33 d3 89 5c 24 ?? 41 c1 ca ?? 48 83 6d } //5
		$a_01_1 = {41 0f b6 0c 01 30 08 48 8d 40 01 48 83 ea 01 75 ef } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}