
rule Trojan_Win32_Guloader_SIBU13_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 81 34 07 90 01 04 90 02 a0 83 c0 04 90 02 6a 83 c1 00 90 02 30 3d 90 01 04 90 02 30 0f 85 90 01 04 90 02 ba ff d7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}