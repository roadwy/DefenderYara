
rule Trojan_Win32_Obfuscator_QQ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 03 4d f0 13 55 f4 89 0d 90 01 04 a1 90 01 04 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d ec 8b 15 90 01 04 89 91 90 01 04 a1 90 01 04 83 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}