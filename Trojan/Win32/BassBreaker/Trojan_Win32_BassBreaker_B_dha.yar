
rule Trojan_Win32_BassBreaker_B_dha{
	meta:
		description = "Trojan:Win32/BassBreaker.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 32 31 33 34 37 31 30 36 30 34 32 31 34 35 } //1 021347106042145
		$a_41_1 = {30 8d 85 8c fe ff ff b9 c4 5c 08 10 50 e8 05 49 00 00 6a 32 8d 8d a4 fe ff ff c7 45 fc 00 00 00 00 51 8b c8 e8 ee 48 00 00 6a 31 8d 8d bc fe ff ff c6 45 fc 01 51 8b c8 e8 da 48 00 00 6a 33 8d 8d d4 fe ff ff c6 45 fc 02 51 8b c8 e8 c6 48 00 00 6a 34 8d 8d ec fe ff ff c6 45 fc 03 51 8b c8 e8 b2 48 00 00 6a 37 8d 8d 04 ff ff ff c6 45 fc 04 51 8b c8 e8 9e 48 00 00 6a 31 8d 8d 1c ff ff ff c6 45 fc 05 51 8b c8 e8 8a 48 00 00 6a 30 8d 8d 34 ff ff ff c6 45 fc 06 51 8b c8 e8 76 48 00 00 6a 36 8d 8d 4c ff ff ff c6 45 fc 07 51 8b c8 e8 62 48 00 00 6a 30 8d 8d 64 ff ff ff c6 45 fc 08 51 8b c8 e8 4e 48 00 00 6a 34 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_41_1  & 1)*1) >=2
 
}