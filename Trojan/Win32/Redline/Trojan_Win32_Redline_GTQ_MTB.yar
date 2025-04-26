
rule Trojan_Win32_Redline_GTQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e8 8b 45 f4 81 45 ?? 47 86 c8 61 33 c1 2b f8 83 6d d8 01 89 45 f4 89 1d } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}