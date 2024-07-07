
rule Trojan_Win32_Hancitor_GJ_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ce 2b cf 83 c1 90 01 01 01 3d 90 02 04 11 2d 90 02 04 8b ef 0f af ee 69 ed 90 02 04 8b f5 89 35 90 02 04 81 c2 90 02 04 8b ef 2b eb 89 10 8d 4c 29 90 01 01 83 c0 04 83 6c 24 90 01 01 01 89 0d 90 02 04 89 15 90 02 04 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}