
rule Trojan_Win32_Babar_SX_MTB{
	meta:
		description = "Trojan:Win32/Babar.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c4 10 8a 06 04 5c 0f b6 c0 83 c0 03 24 fc } //15
		$a_03_1 = {0f af c1 8b 4c 24 ?? a3 ?? ?? ?? ?? 8b 44 24 04 8b d0 03 c1 23 d1 66 a3 } //10
		$a_03_2 = {8b 74 24 1c a3 ?? ?? ?? ?? 8b 5c 24 18 33 c9 8a 06 04 5c 38 0d } //5
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=30
 
}