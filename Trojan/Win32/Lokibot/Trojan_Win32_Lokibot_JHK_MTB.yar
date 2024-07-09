
rule Trojan_Win32_Lokibot_JHK_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 0c 00 66 8b 06 74 0e 66 3b 44 4d ?? 75 0e 66 8b ?? ?? ?? eb 13 66 3b ?? ?? ?? 74 07 41 3b cf 72 dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}