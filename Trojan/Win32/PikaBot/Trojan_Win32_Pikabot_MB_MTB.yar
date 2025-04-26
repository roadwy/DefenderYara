
rule Trojan_Win32_Pikabot_MB_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 08 8b 85 [0-04] 33 d2 be [0-04] f7 f6 0f b6 54 15 a8 33 ca } //5
		$a_03_1 = {03 45 fc 2b 85 ?? ?? ?? ?? 2b 45 a0 8b 95 ?? ?? ?? ?? 88 0c 02 e9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}