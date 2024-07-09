
rule Trojan_Win32_Obfuscator_QW_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 37 56 e8 ?? ?? ?? ?? 8b f0 83 c4 04 3b f3 0f ?? ?? ?? ?? ?? 5f 5e 5b c9 c3 55 8b ec 81 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}