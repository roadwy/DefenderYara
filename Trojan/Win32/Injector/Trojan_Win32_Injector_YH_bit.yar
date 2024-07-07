
rule Trojan_Win32_Injector_YH_bit{
	meta:
		description = "Trojan:Win32/Injector.YH!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8b 90 01 01 08 68 60 e8 00 00 90 00 } //1
		$a_03_1 = {55 89 e5 8b 90 01 01 08 c7 90 01 01 60 e8 00 00 90 00 } //1
		$a_03_2 = {55 89 e5 8b 90 01 01 08 c7 90 01 01 39 97 29 1f 81 90 01 01 59 7f 29 1f 90 00 } //1
		$a_01_3 = {89 c3 be 20 2b 40 00 81 fe 20 2b 40 00 73 0d ff 16 83 c6 04 81 fe 20 2b 40 00 72 f3 } //5
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*5) >=6
 
}