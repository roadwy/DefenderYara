
rule Trojan_Win32_TrickBotCrypt_EB_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 3b 4d f4 73 90 01 01 8b 55 e8 0f b6 02 0f b6 4d e7 33 c1 8b 55 e8 2b 55 08 0f b6 ca 81 e1 e0 00 00 00 33 c1 8b 55 e8 88 02 8b 45 e8 03 45 fc 89 45 e8 eb cb 90 00 } //5
		$a_81_1 = {3c 64 5a 34 4f 48 33 57 3e 4d 21 68 59 28 5f 34 5e 44 76 39 37 37 62 76 56 39 45 38 55 3e 26 46 39 5e 79 40 69 6d 72 3c 29 26 67 2b 48 29 39 54 6e 4a 77 44 66 5f 2a 33 69 44 36 46 31 67 26 5e 2a 4d 4c 70 4f 31 39 48 4e 53 70 41 32 51 5f 3f 65 3e 5e 70 21 6f 65 39 64 76 2a 45 6c 76 39 50 37 3f 70 40 } //5 <dZ4OH3W>M!hY(_4^Dv977bvV9E8U>&F9^y@imr<)&g+H)9TnJwDf_*3iD6F1g&^*MLpO19HNSpA2Q_?e>^p!oe9dv*Elv9P7?p@
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5) >=5
 
}
rule Trojan_Win32_TrickBotCrypt_EB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {03 d0 03 c1 0f b6 1c 10 02 5d 90 01 01 8b 45 90 01 01 02 1d 90 01 04 8b 55 90 01 01 30 1c 10 40 89 45 90 01 01 3b 45 90 01 01 72 90 00 } //5
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {41 56 74 79 70 65 5f 69 6e 66 6f } //1 AVtype_info
		$a_81_3 = {53 65 6d 69 54 72 61 6e 73 70 61 72 65 6e 74 44 69 61 6c 6f 67 57 69 74 68 53 74 61 6e 64 61 72 64 43 74 72 6c 73 2e 70 64 62 } //1 SemiTransparentDialogWithStandardCtrls.pdb
		$a_81_4 = {4d 46 43 2d 45 78 61 6d 70 6c 65 73 2d 6d 61 69 6e 5c 4d 46 43 2d 45 78 61 6d 70 6c 65 73 2d 6d 61 69 6e } //1 MFC-Examples-main\MFC-Examples-main
		$a_81_5 = {4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b } //1 NoEntireNetwork
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}