
rule Trojan_Win32_Emotet_PEF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c2 8b 8d ?? ?? ?? ?? 33 d2 8a 94 0d ?? ?? ?? ?? 03 c2 99 f7 bd ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 32 84 15 ?? ?? ?? ?? 88 85 } //1
		$a_81_1 = {63 49 4e 70 35 4e 4a 71 74 74 53 5a 73 67 66 42 45 74 4a 6b 7a 6a 71 4a 71 41 67 6e 4d 56 4e 49 6d 57 48 } //1 cINp5NJqttSZsgfBEtJkzjqJqAgnMVNImWH
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}