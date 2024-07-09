
rule Trojan_Win32_Obfuscator_RQ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 da 89 1d ?? ?? ?? ?? 83 d0 ?? 89 44 24 24 a3 ?? ?? ?? ?? 8b 44 24 1c 8d 34 56 81 c1 ?? ?? ?? ?? 83 c6 ?? 03 f7 89 08 83 c0 ?? ff 4c 24 14 89 44 24 1c 8b 44 24 24 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}