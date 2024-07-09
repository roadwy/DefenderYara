
rule Trojan_Win32_Trickbot_HD_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 f8 03 c2 0f b6 14 33 89 45 08 8b 45 fc 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 58 2b 05 ?? ?? ?? ?? 0f af c1 0f af c1 48 0f af c1 03 fa 03 c7 8a 0c 30 8b 45 08 30 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}