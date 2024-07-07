
rule Trojan_Win32_Injector_KRT_MTB{
	meta:
		description = "Trojan:Win32/Injector.KRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 05 b8 0b d8 09 bf 04 ef 01 12 25 00 ff 03 1b 00 00 00 05 05 00 4c 69 73 74 33 00 08 04 b8 0b d8 09 bf 04 c2 01 11 24 00 ff 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}