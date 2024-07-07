
rule Trojan_Win32_Obfuscator_PL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 55 f8 8b 0c 90 8b 5d 14 8b 45 fc 33 0c 83 8b 55 08 8b 45 f8 89 0c 82 8b 55 18 4a 3b 55 fc 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}