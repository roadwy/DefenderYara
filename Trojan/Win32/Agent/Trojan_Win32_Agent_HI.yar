
rule Trojan_Win32_Agent_HI{
	meta:
		description = "Trojan:Win32/Agent.HI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {04 e0 3c 5f 77 90 01 01 83 e0 7f 0f a3 90 00 } //01 00 
		$a_00_1 = {83 fe 42 75 2d f7 c7 00 00 00 80 75 25 } //01 00 
		$a_00_2 = {26 70 61 73 73 3d } //01 00  &pass=
		$a_00_3 = {68 74 74 70 3a 2f 2f 32 30 76 70 2e 63 6e 2f 6d 6f 79 75 2f } //00 00  http://20vp.cn/moyu/
	condition:
		any of ($a_*)
 
}