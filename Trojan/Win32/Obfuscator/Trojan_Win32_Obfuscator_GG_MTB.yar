
rule Trojan_Win32_Obfuscator_GG_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 14 39 8d 04 39 41 3b ce 72 90 01 01 33 c9 85 f6 74 90 01 01 30 14 39 8d 04 39 41 3b ce 72 90 01 01 57 e8 90 01 04 83 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}