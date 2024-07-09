
rule Trojan_Win32_Lokibot_BC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 04 00 00 00 f7 f1 8b ?? ?? 0f be ?? ?? 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f8 88 81 90 1b 03 90 13 8b 55 ?? 83 c2 01 89 55 ?? 81 7d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Lokibot_BC_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c9 eb 01 [0-10] 43 eb [0-10] 0b 0f eb [0-10] 31 d9 eb [0-10] 39 c1 75 ?? eb [0-10] eb [0-10] 89 de eb [0-10] eb [0-10] b9 ?? ?? ?? ?? eb [0-10] eb [0-10] 81 f1 ?? ?? ?? ?? eb [0-10] eb [0-10] 81 f1 ?? ?? ?? ?? eb [0-10] eb [0-10] 81 c1 ?? ?? ?? ?? eb 82 eb 35 eb dd eb 6e 29 d2 eb 31 eb d5 03 11 eb e2 eb 3d bb fd d2 5e 00 eb ca eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}