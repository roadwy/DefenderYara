
rule Trojan_Win32_Guloader_SIBU11_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 81 34 07 90 01 04 90 02 90 83 c0 04 90 02 9a 3d 90 01 04 90 02 2a 0f 85 90 01 04 90 02 8a ff d7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}