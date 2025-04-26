
rule Trojan_Win32_Obfuscator_PT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 bd 74 ff ff ff 89 95 68 ff ff ff 8b 45 84 03 85 6c ff ff ff 0f be 08 8b 95 68 ff ff ff 0f be 44 15 8c 33 c8 8b 55 84 03 95 6c ff ff ff 88 0a eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}