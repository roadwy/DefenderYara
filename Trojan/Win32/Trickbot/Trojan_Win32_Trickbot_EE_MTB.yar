
rule Trojan_Win32_Trickbot_EE_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c3 2b d3 89 45 ?? 89 55 ?? 89 7d ?? 8a 0c 02 80 f1 80 3b c6 73 ?? 8b ff 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7 } //1
		$a_02_1 = {6a e0 33 d2 58 f7 f1 3b 45 ?? ?? ?? ?? ?? ?? ?? ?? c7 00 0c 00 00 00 33 c0 5d c3 0f af 4d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}