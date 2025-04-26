
rule Trojan_Win32_LaplasClipper_ALC_MTB{
	meta:
		description = "Trojan:Win32/LaplasClipper.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 31 c0 e8 ?? ?? ?? ?? 8d 05 9c f7 69 00 89 44 24 3c c7 44 24 40 07 00 00 00 8b 05 f8 15 88 00 8b 0d fc 15 88 00 89 44 24 44 89 4c 24 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}