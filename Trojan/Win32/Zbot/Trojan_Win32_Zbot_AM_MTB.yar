
rule Trojan_Win32_Zbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 0c 8b 07 33 d2 89 45 08 33 db 8a 55 0b 8a 5d 0a 8b 14 95 f8 bb 41 00 33 14 9d f8 bf 41 00 33 db 8a dc 25 ff 00 00 00 33 14 9d f8 c3 41 00 33 14 85 f8 c7 41 00 89 17 83 c7 04 49 75 c4 ff 45 14 83 45 0c 20 8b 45 14 3b 86 d0 03 00 00 7c a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}