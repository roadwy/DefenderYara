
rule Trojan_Win32_Emotet_DHB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 b9 d6 48 55 41 8b 54 24 18 8b 74 24 14 81 ca ea 99 e8 54 89 54 24 18 29 f1 8b 54 24 04 89 54 24 24 8b 74 24 0c 8a 1c 06 8b 7c 24 08 88 1c 07 01 c8 8b 4c 24 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}