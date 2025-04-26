
rule Trojan_Win32_Redosdru_E_bit{
	meta:
		description = "Trojan:Win32/Redosdru.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f be 11 0f be 45 f0 2b d0 8b 4d f4 03 4d fc 88 11 8b 55 f4 03 55 fc 0f be 02 0f be 4d ec 33 c1 8b 55 f4 03 55 fc 88 02 eb bf } //1
		$a_03_1 = {fe ff ff 47 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 6f c6 85 ?? fe ff ff 6e c6 85 ?? fe ff ff 67 c6 85 ?? fe ff ff 35 c6 85 ?? fe ff ff 33 c6 85 ?? fe ff ff 38 c6 85 ?? fe ff ff 00 } //1
		$a_03_2 = {8a 0a 32 08 8b 55 ?? 03 55 ?? 88 0a e9 90 09 0c 00 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}