
rule Trojan_Win32_Androm_RB_MTB{
	meta:
		description = "Trojan:Win32/Androm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 8b c8 0f be c2 80 fa 61 7c 03 83 e8 20 8a 56 01 46 03 c8 84 d2 75 e0 8b c1 5e c3 } //1
		$a_01_1 = {cc cc c1 c9 0d 8b c1 c3 cc cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Androm_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ff 00 00 00 7d 0b 8b 4d f0 33 4d f4 89 4d f0 eb e3 8b 55 f0 33 55 ec 83 f2 0f 8b 45 08 03 45 fc 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}