
rule Trojan_Win32_Zbot_RTA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 90 01 01 8b 15 90 01 04 31 02 68 90 01 04 e8 90 01 04 68 90 00 } //1
		$a_03_1 = {33 c0 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 04 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 03 45 90 01 01 03 d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}