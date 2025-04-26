
rule Trojan_Win32_Lokibot_F_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 03 d3 73 [0-20] 8a 12 80 f2 ?? 8b 4d fc 03 c8 73 [0-20] 88 11 ff 45 fc 81 7d fc ?? ?? 00 00 75 } //1
		$a_03_1 = {8b c0 6a 00 e8 ?? ?? ?? ?? c3 53 33 c9 8b d9 03 d8 73 05 e8 ?? ?? ?? ?? 30 13 41 81 f9 ?? ?? 00 00 75 ea 5b c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}