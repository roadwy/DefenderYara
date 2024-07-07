
rule Trojan_Win32_Injector_CVBN_MTB{
	meta:
		description = "Trojan:Win32/Injector.CVBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 bf 04 00 00 00 99 f7 ff 8b 7d e0 8a 04 17 30 04 0b 41 39 f1 7c e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Injector_CVBN_MTB_2{
	meta:
		description = "Trojan:Win32/Injector.CVBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 8b 84 55 04 ff ff ff 33 c8 8b 95 f8 fe ff ff 81 e2 ff ff 00 00 33 ca f7 d1 8b 85 f8 fe ff ff 25 ff ff 00 00 8b 55 08 88 0c 02 66 8b 85 fc fe ff ff 66 05 01 00 66 89 85 fc fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}