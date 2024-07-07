
rule Trojan_Win32_Emotet_DHF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0f 8d 7f 04 33 ca 0f b6 c1 66 89 06 8b c1 c1 e8 08 8d 76 08 0f b6 c0 66 89 46 fa c1 e9 10 0f b6 c1 66 89 46 fc c1 e9 08 0f b6 c1 66 89 46 fe 8b 45 fc 40 89 45 fc 3b c3 72 c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}