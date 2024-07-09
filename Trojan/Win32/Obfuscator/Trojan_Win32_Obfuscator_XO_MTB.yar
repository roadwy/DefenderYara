
rule Trojan_Win32_Obfuscator_XO_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f6 33 c9 88 5d ff 89 45 f8 89 7d f0 85 ff [0-30] 8d 49 00 8d 14 06 8b 45 f4 8a 04 01 30 02 83 f9 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}