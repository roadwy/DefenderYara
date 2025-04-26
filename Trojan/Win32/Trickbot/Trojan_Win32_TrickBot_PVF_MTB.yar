
rule Trojan_Win32_TrickBot_PVF_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PVF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 34 18 81 e1 ff 00 00 00 03 c1 b9 14 02 00 00 99 f7 f9 8a 03 8d 4c 24 10 c7 84 24 34 02 00 00 ff ff ff ff 8a 54 14 18 32 c2 88 03 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}