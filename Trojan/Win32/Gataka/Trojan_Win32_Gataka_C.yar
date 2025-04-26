
rule Trojan_Win32_Gataka_C{
	meta:
		description = "Trojan:Win32/Gataka.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 20 6a 03 8d 4d ?? 51 8d 55 ?? 52 68 89 00 12 00 8d 45 ?? 50 ff 55 } //1
		$a_03_1 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ff ff 68 10 27 00 00 ff 15 ?? ?? ?? ?? c6 45 fc 04 } //1
		$a_03_2 = {68 f8 00 00 00 8d 8d ?? ?? ff ff 51 8b 95 ?? ?? ff ff 52 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}