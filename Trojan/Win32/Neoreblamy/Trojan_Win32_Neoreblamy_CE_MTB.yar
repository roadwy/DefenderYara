
rule Trojan_Win32_Neoreblamy_CE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f af 45 f8 89 45 f8 69 4d f8 ?? 00 00 00 69 45 f8 ?? 00 00 00 2b c8 8b 45 08 03 4d f4 ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72 } //5
		$a_03_1 = {55 8b ec 83 ec ?? 8b 45 08 03 45 0c } //1
		$a_03_2 = {6a 1d 59 33 d2 8b c6 f7 f1 ff 34 97 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f8 03 45 f0 59 59 3b f0 72 } //4
		$a_03_3 = {8b c6 83 e0 3f ff 34 87 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f8 03 45 fc 59 59 3b f0 72 } //4
		$a_03_4 = {2b c8 8b 45 08 2b 4d fc ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72 } //4
		$a_01_5 = {8b 4d fc 8b 45 f8 f7 f1 89 45 fc 8b 45 f4 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*4+(#a_03_3  & 1)*4+(#a_03_4  & 1)*4+(#a_01_5  & 1)*1) >=5
 
}