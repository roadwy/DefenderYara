
rule Trojan_Win32_Emotet_V_MTB{
	meta:
		description = "Trojan:Win32/Emotet.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 51 01 8d 49 00 8a 01 41 84 c0 75 f9 2b ca 8b c6 33 d2 f7 f1 46 8a 82 90 01 04 30 44 3e ff 3b f3 72 d7 8d 45 f8 50 6a 40 53 57 ff 15 90 01 04 8b 45 b0 ff d0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_V_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.V!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 8c 0c 8b f2 8b 54 b4 0c 89 54 8c 0c 0f b6 d0 89 54 b4 0c 8b 44 8c 0c 03 c2 99 f7 fd 0f b6 44 94 0c 30 44 1f ff 3b bc 24 94 07 00 00 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}