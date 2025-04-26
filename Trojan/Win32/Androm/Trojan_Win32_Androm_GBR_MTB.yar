
rule Trojan_Win32_Androm_GBR_MTB{
	meta:
		description = "Trojan:Win32/Androm.GBR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 55 e0 8a 45 fe 4e fe c8 33 c9 3a 45 d0 88 45 fe 8b 45 ec 0f 94 c1 83 f1 0c 0f be c0 09 4d 9c 83 e8 0d 74 09 85 d2 74 05 33 c0 } //1
		$a_01_1 = {8a 4d ff 4e 33 c0 fe 4d fe 80 7d fe 04 0f 94 c0 83 f0 0c 09 45 c8 0f be c1 83 e8 0d 74 09 85 d2 74 05 33 c0 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}