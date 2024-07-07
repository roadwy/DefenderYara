
rule Trojan_Win32_Obfuscator_MS_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 04 40 0f b6 4c 24 2f 03 c1 99 b9 90 01 04 f7 f9 8b 44 24 30 83 c4 1c 8a 4c 14 24 30 08 40 83 bc 24 90 01 05 89 44 24 14 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}