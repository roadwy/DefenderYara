
rule Trojan_Win32_TrickBot_RK_MSR{
	meta:
		description = "Trojan:Win32/TrickBot.RK!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d 0c e8 90 09 00 00 39 45 fc 74 36 8b 4d fc 51 8b 4d 0c e8 9f 09 00 00 89 45 f8 8b 45 fc 33 d2 b9 22 00 00 00 f7 f1 52 8b 4d 08 e8 97 08 00 00 0f be 10 8b 45 f8 0f be 08 33 ca 8b 55 f8 88 0a eb b4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}