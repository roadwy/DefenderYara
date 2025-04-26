
rule Trojan_Win32_Dridex_BR_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BR!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 24 4b 4c 8b 44 24 18 45 8a 0c 08 41 28 d1 4c 8b 54 24 08 45 88 0c 0a 8b 44 24 44 83 c0 20 89 44 24 34 } //10
		$a_01_1 = {4c 8b 54 24 30 45 8a 1a 4c 89 4c 24 58 4c 8b 4c 24 10 45 88 1c 11 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}