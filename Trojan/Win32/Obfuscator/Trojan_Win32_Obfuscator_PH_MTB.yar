
rule Trojan_Win32_Obfuscator_PH_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b fa 8b 55 08 8a d8 d0 eb 33 f6 33 c9 89 45 f4 88 5d ff 89 55 f8 89 7d f0 85 ff ?? ?? 8a 04 01 30 04 32 03 d6 83 f9 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}