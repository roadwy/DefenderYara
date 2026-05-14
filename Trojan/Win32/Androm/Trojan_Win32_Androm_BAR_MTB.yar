
rule Trojan_Win32_Androm_BAR_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 16 83 c3 04 83 c6 04 3b 5d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAR_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c3 04 83 c6 04 3b 5d ?? 0f 82 ?? ?? ?? ?? ba 00 10 00 00 b8 80 de 03 00 03 45 ?? 2b c2 83 c0 04 89 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}