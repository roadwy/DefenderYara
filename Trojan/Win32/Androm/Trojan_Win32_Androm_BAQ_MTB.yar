
rule Trojan_Win32_Androm_BAQ_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 00 10 00 00 b8 80 ae 3b 00 03 45 ?? 2b c2 83 c0 [0-2f] b9 e3 a8 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAQ_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ef 31 d4 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d ?? 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}