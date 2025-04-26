
rule Trojan_Win32_Nebuler_gen_A{
	meta:
		description = "Trojan:Win32/Nebuler.gen!A,SIGNATURE_TYPE_PEHSTR,69 00 69 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 5d f8 ad 8b d8 03 da ad 85 c0 74 3f 8b c8 83 e9 08 85 c9 74 ed 66 c7 45 fe ff ff 66 ad 66 83 7d fe ff 74 04 } //50
		$a_01_1 = {8b 75 fc 8b 4d 0c 0f b6 36 c1 e1 08 0b ce c1 e0 08 ff 45 fc 89 4d 0c 8b 0c 93 8b f0 c1 ee 0b 0f af f1 39 75 0c 73 15 8b c6 be 00 08 00 00 2b f1 c1 ee 05 03 f1 89 34 93 03 d2 eb 16 } //50
		$a_01_2 = {00 45 76 74 53 68 75 74 64 6f 77 6e 00 45 76 74 53 74 61 72 74 75 70 00 69 6e 73 74 00 72 75 6e 00 74 65 73 00 } //5
		$a_01_3 = {00 69 6e 73 74 00 69 6e 73 74 32 00 6d 6f 75 6e 74 00 73 74 61 72 74 75 70 00 74 65 73 00 } //5 椀獮t湩瑳2潭湵t瑳牡畴p整s
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=105
 
}