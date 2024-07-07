
rule Trojan_Win32_Obfuscator_KD_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.KD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 e8 90 01 04 b8 90 01 04 50 e8 90 01 04 b8 90 01 04 31 c9 68 90 01 04 5a 80 34 01 a3 41 39 d1 75 f7 05 90 01 04 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}