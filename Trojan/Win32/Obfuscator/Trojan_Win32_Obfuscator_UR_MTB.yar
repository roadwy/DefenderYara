
rule Trojan_Win32_Obfuscator_UR_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.UR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 03 55 f0 13 45 f4 66 89 55 e8 8b 0d 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 55 e4 a1 90 01 04 89 82 90 01 04 0f b7 4d e8 8b 55 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}