
rule Trojan_Win32_Trickbot_IG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 55 90 02 08 8b 4d 90 01 01 03 4d 90 02 14 33 90 01 01 8b 90 01 02 03 90 01 02 88 90 01 01 e9 90 0a 9b 00 8b 55 90 01 01 83 c2 01 89 55 90 01 01 8b 45 90 01 01 3b 45 90 02 0a 83 c1 01 81 e1 90 01 04 89 4d 90 01 01 8b 55 90 02 0c 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 81 e1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}