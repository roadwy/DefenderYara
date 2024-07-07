
rule Trojan_Win32_Emotet_AC{
	meta:
		description = "Trojan:Win32/Emotet.AC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 4d e0 8a 14 08 8b 75 dc 2a 14 35 90 01 04 8b 7d e8 88 14 0f 83 c1 01 8b 5d f0 39 d9 89 4d e4 73 d2 90 00 } //1
		$a_03_1 = {8b 45 d0 8b 4d d4 ba 32 00 00 00 89 45 cc 89 c8 31 f6 89 55 c8 89 f2 8b 75 c8 f7 f6 89 cf 83 e7 03 8b 5d cc 83 fb 02 0f 47 fa 8a 14 3d 90 01 04 8b 7d e8 8a 34 0f 28 d6 01 cb 8b 75 e4 88 34 0e 83 c1 33 8b 75 ec 39 f1 89 4d d4 89 5d d0 72 af 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}