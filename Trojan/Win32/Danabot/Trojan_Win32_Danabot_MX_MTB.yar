
rule Trojan_Win32_Danabot_MX_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ca c1 e8 05 03 c5 89 4c 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 3d ?? ?? ?? ?? bb 06 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Danabot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 a4 24 e0 00 00 00 8b 84 24 e0 00 00 00 81 84 24 ?? ?? ?? ?? f3 ae ac 68 81 ac 24 ?? ?? ?? ?? b3 30 c7 6b 81 84 24 ?? ?? ?? ?? 21 f4 7c 36 30 0c 1e 4e 0f 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}