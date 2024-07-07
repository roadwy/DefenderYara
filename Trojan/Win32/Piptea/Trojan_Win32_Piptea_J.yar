
rule Trojan_Win32_Piptea_J{
	meta:
		description = "Trojan:Win32/Piptea.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 11 c1 e0 10 c1 ea 10 0b d0 89 15 90 01 04 8b 87 b8 00 00 00 83 c0 90 01 01 89 87 b8 00 00 00 eb 08 61 90 00 } //2
		$a_03_1 = {8b 45 f8 01 45 f4 83 7d f4 90 01 01 72 c5 ff 75 fc e8 90 00 } //1
		$a_01_2 = {8a 06 8a 1f 2a c3 88 06 46 47 84 c0 75 f2 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}