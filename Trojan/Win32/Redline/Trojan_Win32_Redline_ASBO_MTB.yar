
rule Trojan_Win32_Redline_ASBO_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 07 d3 e8 03 c3 33 c2 31 45 fc 8b 45 fc 29 45 f0 81 c7 47 86 c8 61 ff 4d e8 0f 85 } //1
		$a_01_1 = {81 00 e1 34 ef c6 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}