
rule Trojan_Win32_Androm_RR_MTB{
	meta:
		description = "Trojan:Win32/Androm.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 f8 6a 04 68 ?? ?? 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 89 45 ?? b1 ?? ba 90 1b 01 8b 45 90 1b 03 e8 ?? ?? ?? ?? 8d 45 f8 50 68 ?? ?? ?? ?? 68 90 1b 01 8b 45 90 1b 03 50 e8 ?? ?? ?? ?? be e8 1d 04 00 8b 7d 90 1b 03 ff d7 } //1
		$a_03_1 = {ff ff b8 00 00 00 00 f7 f0 89 f6 89 f6 89 f6 [0-2f] 8b c6 5e 5b 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}