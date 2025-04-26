
rule Trojan_Win32_Tofsee_DSK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 0f b7 05 } //1
		$a_02_1 = {30 01 46 3b 74 24 0c 7c 90 09 05 00 e8 } //1
		$a_02_2 = {8b 55 c4 8b c7 c1 e8 05 03 45 b0 03 cb 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 } //2
		$a_02_3 = {8b 54 24 10 8b c7 c1 e8 05 03 44 24 38 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 } //2
		$a_00_4 = {8a 3a 89 f1 0f b6 30 30 df 29 ce 88 38 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_00_4  & 1)*2) >=2
 
}