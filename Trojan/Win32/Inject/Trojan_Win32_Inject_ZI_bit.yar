
rule Trojan_Win32_Inject_ZI_bit{
	meta:
		description = "Trojan:Win32/Inject.ZI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 90 01 02 eb cc 90 00 } //1
		$a_03_1 = {8b 02 89 45 fc 8b 8d 90 01 04 89 4d 90 01 01 8b 55 90 01 01 8b 02 33 85 90 01 04 8b 4d 90 01 01 89 01 90 00 } //1
		$a_03_2 = {8b c9 ff e0 90 09 34 00 0f 85 90 01 04 8b 0d 90 01 04 51 8b 15 90 01 04 52 e8 90 01 04 83 c4 08 a1 90 01 04 05 f0 1b 1b 00 a3 90 01 04 8b ff b8 b0 18 5c 00 8b ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}