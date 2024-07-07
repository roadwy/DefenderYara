
rule Trojan_Win32_NSISInject_EN_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 54 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c8 ff d0 } //5
		$a_03_1 = {88 14 08 8b 45 d4 83 c0 01 89 45 d4 e9 90 01 04 8b 45 e8 ff e0 83 c4 4c 5e 5f 5b 5d c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}