
rule Trojan_Win32_Obfuscator_QL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.QL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 ?? ?? ?? ?? 8b 45 08 89 10 8b 4d 08 8b 11 81 ea ?? ?? ?? ?? 8b 45 08 89 10 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}