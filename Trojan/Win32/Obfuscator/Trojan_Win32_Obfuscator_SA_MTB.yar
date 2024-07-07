
rule Trojan_Win32_Obfuscator_SA_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 bd 7c 90 01 03 89 95 90 01 04 8b 55 f0 03 55 fc 0f be 02 8b 8d 90 01 04 0f be 54 0d 8c 33 c2 8b 4d f0 03 4d fc 88 01 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}