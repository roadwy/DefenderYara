
rule Trojan_Win32_Zegost_CN_bit{
	meta:
		description = "Trojan:Win32/Zegost.CN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 08 8d 42 0c 8b 4a e0 33 c8 } //1
		$a_01_1 = {c6 85 ec fe ff ff 4b c6 85 ed fe ff ff 6f c6 85 ee fe ff ff 74 c6 85 ef fe ff ff 68 c6 85 f0 fe ff ff 65 c6 85 f1 fe ff ff 72 c6 85 f2 fe ff ff 35 c6 85 f3 fe ff ff 39 c6 85 f4 fe ff ff 39 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}