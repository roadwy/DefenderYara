
rule Trojan_Win32_CobaltStrikePacker_GG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrikePacker.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 0f ef c1 0f 11 84 05 90 01 02 ff ff 0f 10 90 01 06 66 0f 90 01 38 66 0f ef c1 0f 11 84 05 90 01 02 ff ff 83 c0 40 3d 90 00 } //20
		$a_00_1 = {80 b4 05 a8 e6 ff ff 1b } //10
		$a_03_2 = {8a 88 e0 0b 01 10 80 f1 90 01 01 88 8c 05 dc fc ff ff 40 3d 90 01 04 72 e8 90 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_00_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}