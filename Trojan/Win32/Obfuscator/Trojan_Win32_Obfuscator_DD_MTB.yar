
rule Trojan_Win32_Obfuscator_DD_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 90 01 04 8a 94 90 01 05 30 10 40 83 bd 90 01 05 89 85 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}