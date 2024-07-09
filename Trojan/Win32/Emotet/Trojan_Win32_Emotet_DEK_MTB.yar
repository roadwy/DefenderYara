
rule Trojan_Win32_Emotet_DEK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8d 4c 24 ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 8a 54 14 ?? 32 c2 88 03 } //1
		$a_81_1 = {51 41 30 6a 58 51 52 6c 43 50 77 4a 6d 6d 62 74 62 45 33 64 53 4b 44 45 58 32 67 59 4f 5a } //1 QA0jXQRlCPwJmmbtbE3dSKDEX2gYOZ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}