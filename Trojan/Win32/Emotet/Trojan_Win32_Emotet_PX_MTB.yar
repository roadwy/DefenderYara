
rule Trojan_Win32_Emotet_PX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f b6 0c 08 33 ca } //1
		$a_03_1 = {2b c1 03 05 ?? ?? ?? ?? 8b 55 ?? 2b c2 8b 4d ?? 8b 55 ?? 88 14 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_PX_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 40 89 44 24 ?? 8a 54 14 ?? 30 50 ?? 39 b4 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 64 89 0d ?? ?? ?? ?? 59 5f 5e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}