
rule Trojan_Win32_Obfuscator_SM_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 03 4d 08 83 e9 ?? ?? ?? ?? ?? ?? 03 d8 83 c4 ?? 58 c9 ?? ?? ?? c1 c9 ?? c0 c8 ?? c0 c8 ?? 34 ?? aa e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}