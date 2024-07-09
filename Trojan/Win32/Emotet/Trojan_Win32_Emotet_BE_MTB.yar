
rule Trojan_Win32_Emotet_BE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a d0 8a cb f6 d1 0a d8 8b 44 24 ?? f6 d2 0a ca 22 cb 88 08 40 83 6c 24 ?? 01 89 44 24 ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d f8 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 55 f8 03 55 f0 8b 45 f8 03 45 f0 8b 4d fc 8b 75 f4 8a 14 16 88 14 01 8b 45 f8 83 c0 01 89 45 f8 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}