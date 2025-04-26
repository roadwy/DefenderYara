
rule Trojan_Win32_Spy_Zbot_ACM{
	meta:
		description = "Trojan:Win32/Spy.Zbot.ACM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 f8 8a 02 88 45 fc 8b 4d 0c 03 4d ec 33 d2 8a 11 8b 45 fc 25 ff 00 00 00 33 d0 8b 4d 0c 03 4d ec 88 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}