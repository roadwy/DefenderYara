
rule Trojan_Win32_Emotet_DHW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHW!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 8b 4d e8 89 0c 90 8b 55 e8 03 55 f0 81 e2 ff 00 00 00 8b 45 10 0f b6 08 8b 45 ec 33 0c 90 8b 55 14 88 0a } //1
		$a_01_1 = {8b 55 fc c1 ea 0d 8b 45 fc c1 e0 13 0b d0 89 55 fc 8b 4d 08 0f b6 11 83 fa 61 7c 0e 8b 45 08 0f b6 08 83 e9 20 89 4d f8 eb 09 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}