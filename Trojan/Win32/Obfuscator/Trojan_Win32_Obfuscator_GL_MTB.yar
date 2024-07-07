
rule Trojan_Win32_Obfuscator_GL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 53 ff 15 90 01 04 53 ff 15 90 01 04 3b f3 90 01 02 e8 90 01 04 30 04 3e 4e 79 f5 8b 4d fc 5f 5e 33 cd 5b e8 90 01 04 c9 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}