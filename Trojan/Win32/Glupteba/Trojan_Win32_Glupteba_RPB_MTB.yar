
rule Trojan_Win32_Glupteba_RPB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 16 41 4f 46 bf ?? ?? ?? ?? 39 de 75 e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPB_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 81 c2 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 c0 04 00 00 00 09 fa 39 f0 75 e1 } //1
		$a_03_1 = {31 30 21 d1 81 c1 ?? ?? ?? ?? 81 c0 04 00 00 00 01 d1 39 f8 75 e5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}