
rule Trojan_Win32_Neoreblamy_BY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b c8 2b ca 03 4d ec ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 f0 59 59 3b f0 72 } //10
		$a_03_1 = {2b c8 03 4d ec ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72 } //10
		$a_03_2 = {2b c8 2b 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72 } //10
		$a_01_3 = {ff ff 89 04 b3 46 8b 45 fc 03 45 f0 59 59 3b f0 72 } //5
		$a_03_4 = {2b c8 2b 4d ?? ff 34 8f ff 34 b3 e8 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*5+(#a_03_4  & 1)*5) >=10
 
}