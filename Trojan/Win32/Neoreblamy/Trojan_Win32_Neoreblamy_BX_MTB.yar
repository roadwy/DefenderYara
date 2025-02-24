
rule Trojan_Win32_Neoreblamy_BX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 f1 ff 34 97 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f8 03 45 fc 59 59 3b f0 72 } //5
		$a_03_1 = {33 d2 8b c6 f7 f1 8b 45 f8 ff 34 97 ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d f8 89 04 b1 46 8b 45 f4 03 c3 3b f0 72 } //5
		$a_03_2 = {59 33 d2 8b c6 f7 f1 8b 45 08 ff 34 ?? ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72 } //5
		$a_03_3 = {8b 45 08 8b d6 8b 0c b3 83 e2 3f 8b 14 ?? ?? ?? ?? ff ff 89 04 b3 46 3b f7 72 } //4
		$a_01_4 = {8b c1 23 c2 03 c0 2b c8 8d 04 0a c3 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*4+(#a_01_4  & 1)*1) >=5
 
}