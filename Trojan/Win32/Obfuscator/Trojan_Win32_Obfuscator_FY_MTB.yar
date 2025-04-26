
rule Trojan_Win32_Obfuscator_FY_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 0d d8 30 04 32 83 f9 ?? ?? ?? 33 c9 ?? ?? 41 42 3b 53 ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a ?? ff 73 ?? 56 ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}