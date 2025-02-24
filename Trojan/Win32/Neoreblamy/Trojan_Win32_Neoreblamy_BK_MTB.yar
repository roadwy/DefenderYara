
rule Trojan_Win32_Neoreblamy_BK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 fb 0f af 45 f4 2b c8 } //2
		$a_01_1 = {2b d1 2b d0 ff 34 97 ff 34 b3 e8 } //2
		$a_01_2 = {0f af c8 0f b6 45 fd 2b d1 } //1
		$a_03_3 = {2b c8 0f b6 45 fe 0f af 45 f4 03 c8 03 4d e4 ff 34 8f ff 34 b3 e8 ?? ?? ?? ?? 89 04 b3 46 0f b6 45 ff 59 59 8b 4d ec 2b c8 0f af 4d } //5
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5) >=5
 
}