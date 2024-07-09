
rule Trojan_Win32_Emotet_W_bit{
	meta:
		description = "Trojan:Win32/Emotet.W!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 6f 6f 6b 00 66 61 63 65 00 6c 75 63 6b 00 25 58 25 50 } //1
		$a_03_1 = {eb 23 8b 45 ?? 8b 4d ?? 01 c8 8b 55 ?? 8b 34 ?? 8b 7c 02 04 8b 5d ?? 01 de 8b 4d ?? 11 cf 89 34 02 89 7c 02 04 } //1
		$a_01_2 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //1
		$a_03_3 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 ?? 39 f2 89 55 ?? 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}