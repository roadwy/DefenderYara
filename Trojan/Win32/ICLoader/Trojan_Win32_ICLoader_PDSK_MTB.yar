
rule Trojan_Win32_ICLoader_PDSK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 24 0c 53 8a 1c 01 32 da 88 1c 01 8b 44 24 0c 83 f8 10 5b 75 } //2
		$a_01_1 = {8a 1c 06 8a 14 0a 41 32 da 88 1c 06 8b c1 83 e8 10 5e f7 d8 1b c0 5b 23 c1 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}