
rule Trojan_Win32_Obfuscator_FD_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {75 14 c7 05 90 01 08 c7 05 90 01 08 33 4c 24 50 8b c7 c1 e8 05 03 84 24 90 01 04 89 84 24 90 01 04 89 4c 24 24 81 fa 90 01 06 6a 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}