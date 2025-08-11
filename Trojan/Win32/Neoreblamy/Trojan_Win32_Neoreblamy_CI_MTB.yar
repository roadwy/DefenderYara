
rule Trojan_Win32_Neoreblamy_CI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b c8 8b 45 f4 2b 4d f8 ff 34 8f ff 34 b0 e8 ?? ?? ?? ff 59 59 8b 4d f4 89 04 b1 46 8b 45 f0 03 c3 } //5
		$a_03_1 = {2b c8 03 4d fc ff 34 8b ff 34 b7 e8 ?? ?? ?? ff 89 04 b7 46 8b 45 f4 03 45 f0 59 59 3b f0 0f 82 } //5
		$a_03_2 = {ff 34 8b ff 34 b8 e8 ?? ?? ?? ff 59 59 8b 4d f4 89 04 b9 47 8b 45 f0 03 c6 3b f8 0f 82 } //5
		$a_03_3 = {2b c8 2b 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ?? ff 89 04 b3 46 8b 45 f4 03 45 ec 59 59 3b f0 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5) >=5
 
}