
rule HackTool_Linux_XHide_A_MTB{
	meta:
		description = "HackTool:Linux/XHide.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 89 e5 83 ec 18 ba 3c 93 04 08 a1 8c b0 04 08 8b 4d 08 89 4c 24 08 89 54 24 04 89 04 24 e8 8a fb ff ff c7 04 24 01 00 00 00 e8 0e fc ff ff } //02 00 
		$a_00_1 = {c7 04 24 00 01 00 00 e8 f7 fc ff ff 89 45 ec 8b 45 08 0f b6 00 3c 2e 75 4f c7 44 24 04 ff 00 00 00 8b 45 ec 89 04 24 e8 07 fd ff ff 85 c0 74 2e b8 2f 93 04 08 89 44 24 04 8b 45 ec 89 04 24 e8 df fc ff ff 8b 45 08 89 44 24 04 8b 45 ec 89 04 24 e8 cd fc ff ff 8b 45 ec e9 e6 00 00 00 } //02 00 
		$a_00_2 = {8b 44 24 48 89 44 24 44 83 7c 24 2c 01 7e 56 c7 44 24 08 ff 00 00 00 c7 44 24 04 20 00 00 00 8d 44 24 5c 89 04 24 e8 8d f8 ff ff c6 84 24 5b 01 00 00 00 8b 44 24 50 89 04 24 e8 19 f9 ff ff 89 c2 8b 44 24 50 89 54 24 08 89 44 24 04 8d 44 24 5c 89 04 24 e8 4f f8 ff ff 8b 44 24 24 8d 54 24 5c 89 10 eb 0a } //00 00 
	condition:
		any of ($a_*)
 
}