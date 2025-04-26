
rule Trojan_Win32_Gataka_D{
	meta:
		description = "Trojan:Win32/Gataka.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 03 50 8d 45 ?? c7 45 ?? 18 00 00 00 50 8d 45 fc 68 89 00 12 00 50 89 7d ?? c7 45 ?? 40 00 00 00 89 7d ?? 89 7d ?? ff 55 f8 } //1
		$a_03_1 = {39 5d 08 74 04 3b c3 75 ?? 68 e8 03 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ff ff 68 10 27 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}