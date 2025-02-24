
rule Trojan_Win32_Neoreblamy_BW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc f7 f1 0f af 45 f8 89 45 f8 69 4d f8 ?? 00 00 00 69 45 f8 ?? 00 00 00 2b c8 03 4d ec ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72 } //10
		$a_03_1 = {f7 f1 89 45 f8 8b 45 ec 2d ?? 00 00 00 89 45 ?? 8b 45 ec 0f af 45 f8 89 45 ec 69 45 f8 ?? 00 00 00 89 45 f8 8b 45 ec 8b 4d fc 2b c8 2b 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 ?? 59 59 3b f0 72 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}