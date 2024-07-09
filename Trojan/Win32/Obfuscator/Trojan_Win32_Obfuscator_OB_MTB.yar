
rule Trojan_Win32_Obfuscator_OB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 42 8b 45 f8 0f b6 44 10 ff 32 c3 8b d8 8d 45 e4 8b d3 e8 ?? ?? ?? ?? 8b 55 e4 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f4 46 ff 4d f0 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}