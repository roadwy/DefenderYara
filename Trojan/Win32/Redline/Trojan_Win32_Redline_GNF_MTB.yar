
rule Trojan_Win32_Redline_GNF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f ?? 80 07 ?? 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 6a 6f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}