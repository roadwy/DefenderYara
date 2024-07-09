
rule Backdoor_Win32_Votwup_A{
	meta:
		description = "Backdoor:Win32/Votwup.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {75 25 8d 45 f8 50 8b 45 fc e8 ?? ?? ff ff 8b c8 ba 05 00 00 00 8b 45 fc e8 ?? ?? ff ff b2 01 8b 45 f8 e8 ?? ?? ff ff 68 60 ea 00 00 e8 ?? ?? ff ff e9 } //5
		$a_01_1 = {2f 67 65 74 63 6d 64 2e 70 68 70 } //2 /getcmd.php
		$a_01_2 = {2f 6e 65 77 62 6f 74 2e 70 68 70 } //2 /newbot.php
		$a_01_3 = {3f 75 69 64 3d } //2 ?uid=
		$a_01_4 = {77 74 66 00 } //1 瑷f
		$a_01_5 = {64 64 31 00 } //1 摤1
		$a_01_6 = {64 64 32 00 } //1 摤2
		$a_01_7 = {75 70 64 00 } //1 灵d
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}