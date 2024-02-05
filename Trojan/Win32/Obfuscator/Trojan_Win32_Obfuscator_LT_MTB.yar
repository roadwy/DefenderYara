
rule Trojan_Win32_Obfuscator_LT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.LT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 ec 0f b6 44 05 00 0f b6 4d f3 03 c1 99 8b cb f7 f9 8b 45 e8 8a 4c 15 00 30 08 40 83 bd 90 01 05 89 45 e8 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}