
rule Trojan_Win32_Emotet_PVT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVT!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 30 88 cc 0f b6 cc 66 c7 84 24 86 00 00 00 00 00 8b 54 24 34 8a 24 0a 30 c4 c6 44 24 73 56 8b 4c 24 24 88 24 31 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}