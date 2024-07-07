
rule PWS_Win32_Zbot_FAL{
	meta:
		description = "PWS:Win32/Zbot.FAL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 38 ff 24 90 01 01 8b 55 f8 8a 54 32 ff 80 e2 90 01 01 32 c2 25 90 01 04 b9 90 01 04 33 d2 f7 f1 8b da 80 f3 90 01 01 8d 45 fc e8 90 01 02 ff ff 8b 55 fc 8a 54 3a ff 80 e2 90 01 01 02 d3 88 54 38 ff 46 8b 45 f8 e8 90 01 02 ff ff 3b f0 7e 05 be 01 00 00 00 47 ff 4d f0 75 a8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}