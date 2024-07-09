
rule Trojan_Win32_Obfuscator_EN_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 0f b6 44 14 24 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 18 8b 4c 24 1c 83 c0 01 89 44 24 18 8a 54 14 24 30 54 01 ff 83 7c 24 14 00 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}