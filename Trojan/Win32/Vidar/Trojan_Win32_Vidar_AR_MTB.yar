
rule Trojan_Win32_Vidar_AR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 0e 32 c8 8b 45 a0 40 88 0e 89 45 a0 3b 45 } //3
		$a_01_1 = {f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}