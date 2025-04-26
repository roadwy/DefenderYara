
rule Trojan_Win32_Zbot_AK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 03 43 33 d2 81 fb e1 32 41 00 75 f3 40 b9 00 00 00 00 33 c8 33 c9 3d e5 99 01 00 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}