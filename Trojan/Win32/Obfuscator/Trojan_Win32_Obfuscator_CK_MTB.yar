
rule Trojan_Win32_Obfuscator_CK_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 f0 8b 45 ec 0f b6 84 05 90 01 04 03 c1 b9 90 01 04 99 f7 f9 8b 45 f0 8a 8c 15 90 01 04 30 08 ff 45 08 8b 45 14 ff 4d 14 85 c0 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}