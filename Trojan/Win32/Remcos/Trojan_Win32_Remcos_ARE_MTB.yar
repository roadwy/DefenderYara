
rule Trojan_Win32_Remcos_ARE_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 b5 f8 fb ff ff 89 b5 e8 fb ff ff 89 b5 d8 fb ff ff 89 b5 c8 fb ff ff 89 b5 b8 fb ff ff 89 b5 a8 fb ff ff 89 b5 98 fb ff ff 89 b5 88 fb ff ff 56 89 b5 78 fb ff ff 89 b5 68 fb ff ff 89 b5 58 fb ff ff 89 b5 48 fb ff ff 89 b5 38 fb ff ff 89 b5 28 fb ff ff 89 b5 18 fb ff ff 89 b5 08 fb ff ff 89 b5 f8 fa ff ff 89 b5 e8 fa ff ff 89 b5 d8 fa ff ff 89 b5 c8 fa ff ff } //00 00 
	condition:
		any of ($a_*)
 
}