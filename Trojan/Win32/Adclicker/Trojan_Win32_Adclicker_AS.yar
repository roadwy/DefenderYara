
rule Trojan_Win32_Adclicker_AS{
	meta:
		description = "Trojan:Win32/Adclicker.AS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {74 65 73 74 90 01 06 2e 64 6c 6c 90 00 } //1
		$a_01_1 = {41 67 65 6e 74 25 6c 64 } //1 Agent%ld
		$a_02_2 = {55 8b ec 83 ec 90 01 01 53 56 33 f6 57 8d 45 90 01 01 56 8b f9 50 ff 15 90 01 04 85 c0 0f 84 90 01 04 6a 40 8d 45 90 01 01 56 50 e8 90 01 04 83 c4 0c ff 15 90 01 04 50 8d 45 90 01 01 68 90 01 04 50 ff 15 90 01 04 83 c4 0c f6 45 90 01 02 56 56 56 75 04 6a 04 eb 01 56 8d 45 90 01 01 50 90 00 } //1
		$a_02_3 = {33 db eb 76 8b 06 6a 02 6a 00 8b ce ff 50 30 ff 75 f0 8b 06 8d 8d e0 fe ff ff 51 8b ce ff 50 40 8b 06 6a 01 68 90 01 04 8b ce ff 50 40 8b 07 6a 02 6a 00 8b cf ff 50 30 ff 75 f0 8b 07 8d 8d e0 fe ff ff 51 8b cf ff 50 40 8b 07 6a 01 68 90 01 04 8b cf ff 50 40 6a 05 6a 00 8d 85 e0 fe ff ff 6a 00 50 8b cb e8 90 01 04 50 6a 00 6a 00 ff 15 90 01 04 6a 01 5b 8d 4d e0 90 00 } //1
		$a_02_4 = {6a 01 58 89 83 90 01 04 8b d8 e9 1b 01 00 00 8d 83 90 01 04 50 8d 85 e0 fd ff ff 50 e8 90 01 04 8d 85 e0 fe ff ff 50 8d 85 e0 fd ff ff 50 e8 90 01 04 83 c4 10 8b cb 68 90 01 04 e8 90 01 04 50 8d 85 e0 fe ff ff 50 e8 90 01 04 59 59 68 90 01 04 8b cb e8 90 01 04 50 8d 85 e0 fd ff ff 50 e8 90 01 04 59 8d 83 90 01 04 59 50 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}