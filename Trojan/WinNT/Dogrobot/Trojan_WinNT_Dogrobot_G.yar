
rule Trojan_WinNT_Dogrobot_G{
	meta:
		description = "Trojan:WinNT/Dogrobot.G,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 e4 10 00 00 c0 8b 4d 0c 8b 41 60 8b 50 0c 89 55 e0 8b 49 0c 89 4d dc 8b 40 04 89 45 d8 60 f5 61 81 7d e0 04 20 22 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}