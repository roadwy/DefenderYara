
rule Trojan_Win32_Obfuscator_EE_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 8c 8a 54 15 ?? 30 10 40 83 bd ?? ?? ?? ?? ?? 89 45 8c 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}