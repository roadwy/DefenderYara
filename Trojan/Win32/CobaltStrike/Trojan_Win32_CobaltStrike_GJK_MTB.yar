
rule Trojan_Win32_CobaltStrike_GJK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca c1 ea 90 01 01 89 d0 f7 e3 89 c8 6b d2 1c 29 d0 0f b6 84 05 90 01 04 30 04 0e 83 c1 01 81 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_CobaltStrike_GJK_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {23 cf c1 c8 16 33 d0 89 5d d8 8b 45 e4 03 d6 23 45 e0 8b 75 ac 0b c1 8b 4d fc 03 c2 33 4d f0 8b d3 89 45 c8 23 cb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}