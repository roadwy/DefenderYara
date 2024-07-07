
rule Trojan_Win32_Redline_WY_MTB{
	meta:
		description = "Trojan:Win32/Redline.WY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 84 24 90 01 04 83 c8 20 89 44 24 90 01 01 e9 90 01 04 0f be 84 24 90 01 04 89 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 31 c8 69 c0 93 01 00 01 89 84 24 90 01 04 e9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}