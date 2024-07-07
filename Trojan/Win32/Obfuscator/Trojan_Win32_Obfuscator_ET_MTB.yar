
rule Trojan_Win32_Obfuscator_ET_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.ET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 f0 e8 90 01 04 0f b6 4d f3 0f b6 03 03 c1 99 8b cf f7 f9 8b 45 e8 8a 4c 15 00 30 08 40 83 bd 90 01 05 89 45 e8 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}