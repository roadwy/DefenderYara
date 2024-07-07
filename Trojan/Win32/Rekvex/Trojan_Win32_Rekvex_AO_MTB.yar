
rule Trojan_Win32_Rekvex_AO_MTB{
	meta:
		description = "Trojan:Win32/Rekvex.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f8 c1 e1 03 d3 ee 33 d6 8b 45 f8 8b 4d 08 8d 04 81 8b 4d f4 88 14 08 eb 97 } //2
		$a_01_1 = {33 45 f8 8b 4d fc 8b 55 08 89 44 8a 18 e9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}