
rule Trojan_Win32_Trickbot_PA{
	meta:
		description = "Trojan:Win32/Trickbot.PA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 02 01 d0 c1 e0 03 03 45 d4 8b 40 0c 89 c2 03 55 dc 8b 45 cc 89 cb 89 d7 89 de 89 c1 f3 a4 66 ff 45 e6 66 8b 45 e6 66 3b 45 da 0f 92 c0 84 c0 75 97 8b 45 e0 83 e8 80 89 45 c8 8b 45 e0 8b 50 28 8b 45 dc 01 d0 89 45 c4 8b 45 c4 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}