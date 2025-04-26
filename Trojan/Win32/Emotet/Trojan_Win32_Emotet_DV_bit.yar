
rule Trojan_Win32_Emotet_DV_bit{
	meta:
		description = "Trojan:Win32/Emotet.DV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //1
		$a_03_1 = {15 18 00 00 00 31 ?? 8b ?? 30 8b ?? 0c } //1
		$a_03_2 = {31 d2 f7 f1 8b 0d ?? ?? ?? ?? 8a 1c 11 8b 4d ?? 8b 55 ?? 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 ?? 39 f2 89 55 ?? 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}