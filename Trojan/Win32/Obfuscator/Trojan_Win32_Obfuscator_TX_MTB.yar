
rule Trojan_Win32_Obfuscator_TX_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.TX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 30 8a 18 83 c4 1c 8a 54 14 18 32 da 88 18 40 89 44 24 14 ff 4c 24 10 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Obfuscator_TX_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.TX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0a 80 f1 ?? 8b 5d fc 03 d8 ?? ?? e8 ?? ?? ?? ?? 88 0b eb 10 8b 4d fc 03 c8 73 05 e8 ?? ?? ?? ?? 8a 1a 88 19 40 42 3d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}