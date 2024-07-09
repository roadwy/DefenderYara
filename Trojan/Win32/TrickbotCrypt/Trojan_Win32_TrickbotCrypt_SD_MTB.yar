
rule Trojan_Win32_TrickbotCrypt_SD_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 8b 74 24 ?? 85 f6 7e ?? 8b 44 24 ?? 8b 4c 24 ?? 2b c8 8a 14 01 80 ea ?? 88 10 83 c0 01 83 ee 01 75 ?? 5e c3 } //1
		$a_03_1 = {6a 40 68 00 30 00 00 68 01 08 00 00 b9 0b 00 00 00 be ?? ?? ?? ?? 8d 7c 24 ?? 6a 00 f3 a5 ff 15 ?? ?? ?? ?? 8b f0 e8 ?? ?? ?? ?? 85 c0 75 ?? 68 00 08 00 00 56 68 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}