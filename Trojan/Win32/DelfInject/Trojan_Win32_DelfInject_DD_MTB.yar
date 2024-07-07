
rule Trojan_Win32_DelfInject_DD_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 83 8c 01 00 00 b2 01 a1 38 1b 42 00 } //1
		$a_01_1 = {8b f0 89 b3 70 01 00 00 8b 53 70 } //1
		$a_01_2 = {a0 a0 9d 45 00 88 83 62 01 00 00 c6 83 63 01 00 00 02 c6 83 64 01 00 00 01 c7 83 68 01 00 00 01 00 00 00 c6 83 50 01 00 00 01 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}