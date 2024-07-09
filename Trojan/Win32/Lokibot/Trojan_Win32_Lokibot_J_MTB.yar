
rule Trojan_Win32_Lokibot_J_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {41 39 d1 75 f7 90 0a 1f 00 ba ?? ?? 00 00 31 c9 80 34 01 a3 41 39 d1 75 f7 05 ?? ?? 00 00 ff e0 } //1
		$a_02_1 = {51 54 6a 40 68 ?? ?? 00 00 50 e8 ?? ?? ?? ff 5a c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}