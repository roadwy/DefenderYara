
rule Trojan_Win32_Emotet_DHA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {41 81 e1 ff 00 00 00 8b 3c 8d ?? ?? ?? ?? 03 c7 25 ff 00 00 00 8a 14 85 ?? ?? ?? ?? 89 3c 85 70 a8 42 00 0f b6 d2 89 14 8d ?? ?? ?? ?? 8b 3c 85 ?? ?? ?? ?? 03 fa 81 e7 ff 00 00 00 0f b6 14 bd ?? ?? ?? ?? 30 14 2e 83 ee 01 79 b4 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}