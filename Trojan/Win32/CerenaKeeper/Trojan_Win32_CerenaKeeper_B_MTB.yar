
rule Trojan_Win32_CerenaKeeper_B_MTB{
	meta:
		description = "Trojan:Win32/CerenaKeeper.B!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 24 99 8b 4d f4 2b c8 8b 55 20 89 0a 8b 45 24 99 8b 4d f0 89 41 28 89 51 2c 8b 55 f0 8b 45 f4 89 42 30 8b 4d f8 89 4a 34 8b 55 f0 c6 42 6c 01 } //1
		$a_01_1 = {8b 45 f8 33 c9 8b 55 f4 03 42 20 13 4a 24 8b 55 f4 89 42 20 89 4a 24 8b 45 ec 03 45 f8 89 45 ec 8b 4d 0c 2b 4d f8 89 4d 0c eb 86 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}