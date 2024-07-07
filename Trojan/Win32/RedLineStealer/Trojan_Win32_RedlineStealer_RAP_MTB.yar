
rule Trojan_Win32_RedlineStealer_RAP_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.RAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 4d d0 89 08 8b 55 08 8b 45 f4 89 42 04 81 3d 90 01 08 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}