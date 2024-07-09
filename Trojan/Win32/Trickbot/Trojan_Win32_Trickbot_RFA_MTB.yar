
rule Trojan_Win32_Trickbot_RFA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c9 66 8b 0b 8d 3c 8a 8b 4c 24 ?? 8a 15 ?? ?? ?? ?? 03 f8 8b 31 33 c9 03 f0 84 d2 74 ?? 8b ee 81 ed ?? ?? ?? ?? 8a 94 29 ?? ?? ?? ?? 84 d2 74 } //1
		$a_01_1 = {5a 4d 3f 4a 67 45 6c 62 2a 52 68 61 21 2b 5a } //1 ZM?JgElb*Rha!+Z
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}