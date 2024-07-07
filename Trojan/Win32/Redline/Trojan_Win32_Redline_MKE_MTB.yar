
rule Trojan_Win32_Redline_MKE_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 c1 ea 90 01 01 03 54 24 90 01 01 8d 04 3e 31 44 24 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 89 5c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 2b 74 24 90 01 01 4d 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}