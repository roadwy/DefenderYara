
rule TrojanDropper_Win32_CryptInject_DI_MTB{
	meta:
		description = "TrojanDropper:Win32/CryptInject.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 fb 8b 5d f8 0f b6 c2 89 45 f4 88 55 fd 8a 54 08 04 8d 44 08 04 88 16 8a 55 ff 88 10 8b 45 08 03 d8 0f b6 06 0f b6 d2 03 c2 be 00 01 00 00 99 f7 fe 0f b6 c2 8a 44 08 04 30 03 ff 45 f8 8b 45 f8 3b 45 0c 72 90 } //00 00 
	condition:
		any of ($a_*)
 
}