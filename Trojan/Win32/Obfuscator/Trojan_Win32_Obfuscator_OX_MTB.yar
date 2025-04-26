
rule Trojan_Win32_Obfuscator_OX_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.OX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 18 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 20 32 da 88 1c 01 41 3b ee 89 4c 24 18 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}