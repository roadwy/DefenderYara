
rule Trojan_Win32_Copak_GNT_MTB{
	meta:
		description = "Trojan:Win32/Copak.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 06 46 42 01 d3 39 fe 90 01 02 c3 8d 04 08 21 d3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Copak_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 c2 29 d2 31 31 b8 90 01 04 29 c2 81 c1 90 01 04 39 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}