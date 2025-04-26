
rule Trojan_Win32_Trickbot_H_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d6 8b 4c 24 14 33 c0 8a 44 3c 18 81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 54 14 18 32 c2 88 45 00 8b 44 24 10 45 48 89 44 24 10 0f 85 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}