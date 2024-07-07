
rule Trojan_Win32_Redline_MKRL_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 d3 e8 8b d5 8d 4c 24 90 01 01 89 44 24 90 01 01 e8 90 01 04 8b 4c 24 90 01 01 33 4c 24 90 01 01 89 35 90 01 04 31 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}