
rule Trojan_Win32_Qukart_ASO_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 ba d3 4d 62 10 51 89 c1 f7 ea c1 fa 07 c1 f9 1f 29 ca 89 d0 59 89 c2 83 c2 61 88 14 37 46 39 de 7c } //00 00 
	condition:
		any of ($a_*)
 
}