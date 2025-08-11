
rule Trojan_Win32_Neoreblamy_CH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {f7 f1 0f af 45 } //2
		$a_03_1 = {ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 } //3
		$a_03_2 = {ff 34 8b ff 34 b8 e8 ?? ?? ff ff 59 59 8b 4d ?? 89 04 b9 47 } //3
		$a_03_3 = {ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 } //3
		$a_03_4 = {ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 } //3
		$a_03_5 = {ff 34 8b ff 34 b7 e8 ?? ?? ff ff 89 04 b7 } //3
		$a_01_6 = {59 59 3b f0 72 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3+(#a_03_5  & 1)*3+(#a_01_6  & 1)*2) >=5
 
}