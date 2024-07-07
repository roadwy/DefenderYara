
rule Trojan_Win32_Redline_MCR_MTB{
	meta:
		description = "Trojan:Win32/Redline.MCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 c1 e0 02 01 d0 01 c0 01 d0 89 c1 8b 55 90 01 01 8b 45 90 01 01 01 d0 31 cb 89 da 88 10 83 45 90 01 02 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}