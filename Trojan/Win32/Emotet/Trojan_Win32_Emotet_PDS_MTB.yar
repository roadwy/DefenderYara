
rule Trojan_Win32_Emotet_PDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 83 c5 01 0f b6 94 14 90 01 04 30 55 90 00 } //1
		$a_81_1 = {6a 49 70 4f 73 4a 36 6b 75 32 58 41 71 59 70 4f 47 77 36 37 5a 78 44 35 68 6c 66 30 6b 41 57 6f 63 70 36 6d } //1 jIpOsJ6ku2XAqYpOGw67ZxD5hlf0kAWocp6m
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_PDS_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 5c 04 0c 30 5c 3c 10 30 5c 3c 14 8b c6 83 e0 03 83 c6 06 8a 54 04 0c 30 54 3c 11 30 54 3c 15 } //2
		$a_02_1 = {2b c8 89 0d 90 01 04 8b 15 90 01 04 81 c2 a4 2b d1 01 89 15 90 01 04 a1 90 01 04 03 45 ec 8b 0d 90 01 04 89 88 90 09 06 00 8b 0d 90 00 } //2
		$a_00_2 = {8b 45 f0 03 45 e8 8d 0c 17 33 c1 81 c7 47 86 c8 61 33 45 e0 2b d8 8b 45 d8 83 ee 01 75 } //2
		$a_00_3 = {0f b6 5d 01 8b cf c1 e1 1c c1 f9 1f 81 e2 64 10 b7 1d 33 c2 81 e1 32 88 db 0e 33 c1 8b cf 8b d7 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}