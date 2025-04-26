
rule Trojan_Win32_Emotet_RZ_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RZ!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 81 8c 00 00 00 83 c7 01 03 54 24 20 03 34 90 b8 56 55 55 55 f7 ee 8b c2 c1 e8 1f 03 c2 8b b4 81 c4 00 00 00 8b 44 24 10 8b 91 00 05 00 00 89 34 10 83 c0 04 3b b9 cc 04 00 00 89 44 24 10 0f 8c 75 ff ff ff } //1
		$a_01_1 = {8b c8 c1 e1 08 0b c8 c1 e1 08 81 c9 ff 00 00 00 83 c6 01 89 0f 83 c7 04 81 fe 00 01 00 00 89 74 24 3c 7c b0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}