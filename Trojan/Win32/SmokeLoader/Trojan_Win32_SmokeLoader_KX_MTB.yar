
rule Trojan_Win32_SmokeLoader_KX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8b 4d 90 01 01 8b de d3 e3 03 45 90 01 01 89 55 90 01 01 89 45 90 01 01 03 5d 90 01 01 33 d8 33 da 89 5d 90 01 01 33 db 89 1d 90 01 04 8b 45 90 01 01 29 45 90 01 01 81 45 90 01 05 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}