
rule Trojan_Win32_Emotet_KA_bit{
	meta:
		description = "Trojan:Win32/Emotet.KA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 8b 90 01 03 88 14 06 8b 90 01 03 81 cf 90 01 04 89 90 01 03 66 8b 90 01 03 66 83 f3 ff 83 c0 01 66 89 90 01 03 8b 90 01 03 39 f8 89 90 01 03 74 af 90 00 } //1
		$a_03_1 = {66 8b 14 41 66 89 d6 66 83 c6 bf 66 89 d7 66 83 c7 20 66 83 fe 1a 66 0f 42 d7 8b 90 01 03 66 39 14 43 0f 94 c1 83 c0 01 8b 90 01 03 39 f0 0f 92 c5 66 83 fa 00 0f 95 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}