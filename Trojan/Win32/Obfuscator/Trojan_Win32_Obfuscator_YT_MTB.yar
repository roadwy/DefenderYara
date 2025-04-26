
rule Trojan_Win32_Obfuscator_YT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.YT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 7d f0 89 55 e4 8b 45 fc 03 45 0c 0f be 08 8b 55 e4 0f be 44 15 10 33 c8 8b 55 fc 03 55 0c 88 0a eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}