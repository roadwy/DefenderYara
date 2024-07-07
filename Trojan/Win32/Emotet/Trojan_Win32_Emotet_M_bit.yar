
rule Trojan_Win32_Emotet_M_bit{
	meta:
		description = "Trojan:Win32/Emotet.M!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 6a 40 68 90 01 03 00 8b 4d f4 51 ff 15 90 01 03 01 ff 55 f4 90 00 } //1
		$a_03_1 = {8b 4d 0c 8b 11 89 55 90 01 01 8b 45 0c 8b 48 04 89 4d 90 01 01 8b 55 0c 8b 42 08 89 45 90 01 01 8b 4d 0c 8b 51 0c 90 00 } //1
		$a_03_2 = {c1 e0 04 03 45 f8 8b 4d f4 03 4d f0 33 c1 8b 55 f4 c1 ea 05 03 55 90 01 01 33 c2 8b 4d 90 01 01 2b c8 89 4d 90 01 01 8b 55 f0 2b 55 90 01 01 89 55 f0 eb 9e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}