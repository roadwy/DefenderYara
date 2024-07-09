
rule Trojan_Win32_Zbot_AR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 13 03 d6 b9 61 21 bc 4c 81 f1 65 21 bc 4c 03 d9 c1 c2 0e 89 55 e8 03 c5 50 e8 ?? ?? ?? ?? 53 5a 58 2b c5 8b 4d bc c1 c9 1b 03 c8 3b c8 0f 85 8c 00 00 00 2b c8 48 3b c1 75 c5 } //1
		$a_00_1 = {b9 5d 36 d3 84 81 f1 59 36 d3 84 03 f9 8b 0f 8b 45 cc c1 c0 0c 3b c8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}