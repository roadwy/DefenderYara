
rule Trojan_Win32_Ovoxual_B{
	meta:
		description = "Trojan:Win32/Ovoxual.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 85 df fe ff ff 45 c6 85 e0 fe ff ff 53 c6 85 e1 fe ff ff 2e c6 85 e2 fe ff ff 44 c6 85 d8 fe ff ff 46 c6 85 d9 fe ff ff 41 c6 85 da fe ff ff 56 c6 85 de fe ff ff 54 c6 85 e3 fe ff ff 41 c6 85 e4 fe ff ff 54 80 a5 e5 fe ff ff 00 } //01 00 
		$a_01_1 = {c6 45 eb 56 c6 45 ec 69 c6 45 ed 65 c6 45 ee 77 c6 45 ef 4f c6 45 f0 66 c6 45 f1 53 c6 45 f2 65 c6 45 f3 63 c6 45 f4 74 c6 45 f5 69 c6 45 f6 6f c6 45 f7 6e c6 45 d8 6e c6 45 d9 74 c6 45 da 64 c6 45 db 6c c6 45 dc 6c c6 45 dd 2e c6 45 de 64 c6 45 df 6c c6 45 e0 6c ff 15 } //01 00 
		$a_01_2 = {c6 45 eb 56 c6 45 ec 69 c6 45 f3 63 c6 45 f4 74 c6 45 f5 69 c6 45 f6 6f c6 45 f7 6e c6 45 d8 6e c6 45 d9 74 c6 45 da 64 c6 45 db 6c c6 45 dc 6c c6 45 dd 2e c6 45 de 64 c6 45 df 6c c6 45 e0 6c ff 15 } //01 00 
		$a_01_3 = {c6 45 f1 76 c6 45 f8 65 c6 45 f5 73 88 5d fb c6 45 f2 63 c6 45 f0 73 c6 45 f6 74 c6 45 f7 2e c6 45 f3 68 c6 45 fa 65 ff 15 } //01 00 
		$a_03_4 = {8b 7d 0c 57 c7 07 07 00 01 00 ff 76 04 ff 15 90 01 04 8b 5d 10 8d 45 08 50 8b 87 a4 00 00 00 6a 04 83 c0 08 53 50 ff 36 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}