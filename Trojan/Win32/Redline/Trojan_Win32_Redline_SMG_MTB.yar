
rule Trojan_Win32_Redline_SMG_MTB{
	meta:
		description = "Trojan:Win32/Redline.SMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 1d 90 01 04 31 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 81 45 90 01 05 ff 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}