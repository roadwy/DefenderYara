
rule Trojan_Win32_Glupteba_B_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 34 24 83 c4 04 e8 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 31 30 ba ?? ?? ?? ?? 40 81 e9 ?? ?? ?? ?? 39 d8 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_B_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 10 43 81 fb 10 00 00 00 75 0e 33 db eb 0a } //10
		$a_02_1 = {49 83 f9 ff 74 74 bb 28 00 00 00 0f af d9 51 a1 ?? ?? ?? ?? 83 c0 10 0f b7 10 03 da } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}