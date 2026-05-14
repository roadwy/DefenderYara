
rule Trojan_Win32_Lokibot_ALI_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.ALI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8a 08 89 db 8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 71 05 e8 ?? ?? ?? ?? 83 c4 08 32 0d ?? ?? ?? ?? 88 08 89 c9 89 db ff 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}