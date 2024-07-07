
rule Trojan_Win32_Trickbot_AO_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 61 6e 74 c7 45 90 01 01 52 65 6c 65 ff 15 90 01 04 68 f8 2a 00 00 ff 90 01 01 eb 90 00 } //1
		$a_03_1 = {2b c1 51 8b cf 81 c1 90 01 02 00 00 c1 e0 02 03 c8 8b 01 59 03 d0 52 90 00 } //1
		$a_03_2 = {0c 8b c5 b9 90 01 01 00 00 00 c1 e1 02 2b c1 8b 00 89 45 90 01 01 6a 90 01 01 59 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}