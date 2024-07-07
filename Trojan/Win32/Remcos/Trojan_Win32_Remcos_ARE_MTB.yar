
rule Trojan_Win32_Remcos_ARE_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 c0 a2 00 00 00 92 8b 03 8b 00 25 ff ff 00 00 50 8b 06 50 ff 15 } //1
		$a_03_1 = {8b 45 fc 0f b6 74 18 ff 8b c6 83 c0 df 83 e8 5e 73 1e 8b 45 f8 e8 90 01 04 8d 44 18 ff 50 8d 46 0e b9 5e 00 00 00 99 f7 f9 83 c2 21 58 88 10 43 4f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Remcos_ARE_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 b5 f8 fb ff ff 89 b5 e8 fb ff ff 89 b5 d8 fb ff ff 89 b5 c8 fb ff ff 89 b5 b8 fb ff ff 89 b5 a8 fb ff ff 89 b5 98 fb ff ff 89 b5 88 fb ff ff 56 89 b5 78 fb ff ff 89 b5 68 fb ff ff 89 b5 58 fb ff ff 89 b5 48 fb ff ff 89 b5 38 fb ff ff 89 b5 28 fb ff ff 89 b5 18 fb ff ff 89 b5 08 fb ff ff 89 b5 f8 fa ff ff 89 b5 e8 fa ff ff 89 b5 d8 fa ff ff 89 b5 c8 fa ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}