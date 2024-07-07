
rule Trojan_Win32_NSISInject_EC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15 } //5
		$a_03_1 = {88 04 39 41 3b cb 72 90 01 01 6a 00 6a 00 57 ff 15 90 01 04 c2 ee 8c 43 f7 d0 5b 42 81 fa d2 ff 00 00 74 90 01 01 c2 4b b6 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}