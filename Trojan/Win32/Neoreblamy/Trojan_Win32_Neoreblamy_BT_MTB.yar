
rule Trojan_Win32_Neoreblamy_BT_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 c7 45 f4 ?? 00 00 00 8b 4d f4 8b 45 f8 f7 f1 0f af 45 f4 8b 4d f8 2b c8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 ?? 59 59 3b f0 } //10
		$a_03_1 = {03 45 e8 89 45 f4 6b 4d f4 24 6b 45 f4 25 2b c8 03 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f0 03 45 ec 59 59 3b f0 } //5
		$a_03_2 = {89 75 f4 33 d2 c7 45 f8 ?? 00 00 00 8b 45 f8 89 45 e8 8b 4d f8 8b 45 f4 f7 f1 89 45 fc } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=10
 
}