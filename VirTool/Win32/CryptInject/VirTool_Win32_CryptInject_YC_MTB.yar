
rule VirTool_Win32_CryptInject_YC_MTB{
	meta:
		description = "VirTool:Win32/CryptInject.YC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 00 03 c3 8a 08 88 4d 13 8a 48 01 88 4d ff 8a 48 02 0f b6 40 03 50 8d 45 fe 50 8d 45 ff 50 8d 45 13 50 88 4d fe e8 8f ff ff ff 8a 45 13 88 04 3e 8a 45 ff 88 44 3e 01 8a 45 fe 88 44 3e 02 8b 45 0c 83 c3 04 83 c6 03 3b 18 72 b1 } //01 00 
		$a_01_1 = {55 8b ec 8a 45 14 8b 4d 08 8a d0 80 e2 f0 c0 e2 02 08 11 8b 4d 0c 8a d0 80 e2 fc c0 e2 04 08 11 8b 4d 10 c0 e0 06 08 01 5d c2 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}