
rule Trojan_Win32_Obfuscator_LL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 db 53 8d 90 01 05 50 53 ff 15 90 01 04 8d 85 90 01 04 50 53 ff 15 90 01 04 85 f6 90 01 02 e8 90 01 04 30 04 3e 4e 79 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Obfuscator_LL_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 d1 00 89 4c 24 0c 89 0d 90 01 04 8b 0d 90 01 04 89 1d 90 01 04 8b 5c 24 24 05 90 01 04 89 44 24 20 a3 90 01 04 89 03 bb 90 01 04 0f b7 05 90 01 04 66 3b c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}