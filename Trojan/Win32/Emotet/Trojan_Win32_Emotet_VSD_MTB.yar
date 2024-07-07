
rule Trojan_Win32_Emotet_VSD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VSD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 0b 45 0c 8b 4d 08 f7 d1 8b 55 0c f7 d2 0b ca 23 c1 eb } //2
		$a_01_1 = {8b 4c 24 08 8b 54 24 0c 8b c1 8b f2 f7 d0 f7 d6 0b c6 0b ca 23 c1 5e c3 } //2
		$a_01_2 = {8b 4c 24 10 8b 54 24 14 8b c1 0b 4c 24 14 f7 d0 f7 d2 0b c2 5f 5e 23 c1 5b c3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=2
 
}