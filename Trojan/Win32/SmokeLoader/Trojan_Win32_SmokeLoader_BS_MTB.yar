
rule Trojan_Win32_SmokeLoader_BS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d c4 8d 45 e0 89 55 e0 e8 90 02 04 8b 45 e0 33 c3 31 45 f8 89 35 90 02 04 8b 45 f4 89 45 e4 8b 45 f8 29 45 e4 8b 45 e4 89 45 f4 81 45 dc 47 86 c8 61 ff 4d d8 0f 90 00 } //2
		$a_01_1 = {81 00 e1 34 ef c6 c3 01 08 c3 01 08 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}