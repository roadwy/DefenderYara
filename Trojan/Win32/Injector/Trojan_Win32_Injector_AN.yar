
rule Trojan_Win32_Injector_AN{
	meta:
		description = "Trojan:Win32/Injector.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b 95 fc fe ff ff 8b 42 50 50 8b 4d 10 51 8b 55 08 8b 02 50 ff 95 90 01 04 6a 00 8b 8d fc fe ff ff 8b 51 54 52 8b 45 0c 50 8b 4d 10 51 8b 55 08 8b 02 50 90 00 } //1
		$a_01_1 = {83 c1 01 89 8d 64 fd ff ff 8b 95 fc fe ff ff 0f b7 42 06 39 85 64 fd ff ff 7d 58 8b 8d 68 fd ff ff 8b 51 3c 8b 45 0c 8d 8c 10 f8 00 00 00 8b 95 64 fd ff ff 6b d2 28 03 ca 89 8d 60 fd ff ff 6a 00 8b 85 60 fd ff ff 8b 48 10 51 8b 95 60 fd ff ff 8b 45 0c 03 42 14 50 8b 8d 60 fd ff ff 8b 55 10 03 51 0c 52 8b 45 08 8b 08 51 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}