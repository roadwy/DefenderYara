
rule Trojan_Win32_Neoreblamy_BN_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 45 ff 0f b6 55 ?? 0f af c8 0f b6 45 ff 0f af d0 2b d1 03 55 ?? 0f af 55 ?? 0f b6 45 } //10
		$a_03_1 = {89 75 fc 33 d2 c7 45 f8 ?? ?? ?? ?? 8b 4d f8 8b 45 fc f7 f1 0f af 45 f8 8b 4d fc 2b c8 ff 34 8f ff 34 b3 e8 ?? ?? ?? ?? 89 04 b3 46 8b 45 } //10
		$a_01_2 = {8b 4d 14 8b 09 0f b6 04 01 50 e8 } //5
		$a_01_3 = {2b c1 8b 4d 14 8b 49 04 0f b6 04 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=10
 
}