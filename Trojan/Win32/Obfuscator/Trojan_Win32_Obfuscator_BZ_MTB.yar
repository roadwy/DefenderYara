
rule Trojan_Win32_Obfuscator_BZ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 e8 f0 90 02 0d 50 e8 90 01 04 b8 90 01 04 31 c9 ba 21 5d 00 00 80 34 01 90 01 01 41 39 d1 75 90 01 01 05 90 01 04 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}