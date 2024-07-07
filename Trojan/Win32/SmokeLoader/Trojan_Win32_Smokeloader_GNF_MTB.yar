
rule Trojan_Win32_Smokeloader_GNF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 8d 4c 24 90 01 01 e8 90 01 04 8b 4c 24 90 01 01 01 5c 24 90 01 01 8d 34 17 d3 ea 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 31 74 24 90 01 01 81 3d 90 01 04 21 01 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}