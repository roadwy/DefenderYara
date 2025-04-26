
rule Trojan_Win32_Obfuscator_XK_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 de 83 c1 ?? f7 de 83 ee ?? 8d 76 fe 8d 76 01 29 fe 31 ff 09 f7 c7 43 ?? ?? ?? ?? ?? 31 33 83 c3 ?? 83 c2 ?? 8d ?? ?? ?? ?? ?? 81 ee ?? ?? ?? ?? ff e6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}