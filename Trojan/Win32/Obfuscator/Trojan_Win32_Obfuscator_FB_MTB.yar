
rule Trojan_Win32_Obfuscator_FB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 0c 32 03 d6 83 f8 ?? ?? ?? 33 c0 eb 01 40 30 1a 8b 4d ?? 8b 55 ?? 46 3b f7 ?? ?? 8b 4d ?? 8b 55 ?? 8a 45 ?? 30 02 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}