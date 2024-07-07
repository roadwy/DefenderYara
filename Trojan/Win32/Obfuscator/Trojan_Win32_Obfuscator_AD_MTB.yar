
rule Trojan_Win32_Obfuscator_AD_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d a4 24 00 00 00 00 8a 4c 05 d8 30 0c 32 83 f8 20 75 04 33 c0 eb 01 40 42 3b d7 72 ea 8b 85 90 01 04 ff d0 6a 00 ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}