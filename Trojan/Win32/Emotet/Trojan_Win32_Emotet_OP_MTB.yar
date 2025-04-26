
rule Trojan_Win32_Emotet_OP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.OP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 04 24 0f b6 4c 24 17 03 c1 99 b9 a1 02 00 00 f7 f9 8b 44 24 20 8b 8c 24 d4 02 00 00 8a 54 14 24 30 14 08 40 89 44 24 20 8b 84 24 d8 02 00 00 85 c0 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}