
rule Trojan_Win32_Zbot_GTT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b ec 8b 4d 10 33 d2 8b 75 04 8b 36 03 f3 33 c0 50 c1 c8 07 31 04 24 ac 84 c0 75 f5 } //10
		$a_02_1 = {d1 e2 8b 4d 00 03 cb 03 ca 8b 09 81 e1 ?? ?? ?? ?? 8b 55 0c 03 d3 c1 e1 02 03 d1 8b 12 03 d3 89 17 8b 4d 08 03 cb 89 4d 04 5f eb 9d } //10
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}