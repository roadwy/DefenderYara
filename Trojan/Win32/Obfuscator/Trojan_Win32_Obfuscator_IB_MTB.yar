
rule Trojan_Win32_Obfuscator_IB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.IB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 66 89 1d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? ?? ?? 8d b8 ?? ?? ?? ?? 8d 41 be 81 c2 ?? ?? ?? ?? 03 c6 89 55 00 8b c8 83 c6 19 2b cf 83 c5 04 03 f1 83 6c 24 14 01 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}