
rule Trojan_Win32_Injector_CR_bit{
	meta:
		description = "Trojan:Win32/Injector.CR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 d2 c1 6d 90 01 01 08 89 5d 90 01 01 89 4d 90 01 01 c7 45 90 01 01 64 00 00 00 8a 4d 90 01 01 02 4d 90 01 01 02 4d 90 01 01 02 c8 02 d1 ff 4d 90 01 01 75 ee 30 97 90 01 04 0f b6 ca 03 cf 03 c1 47 3b fe a3 90 01 04 7c b4 6a 40 68 00 30 00 00 56 6a 00 ff 15 90 00 } //1
		$a_03_1 = {8a 14 0f 88 11 41 4e 75 f7 8b 0d 90 01 04 8d 84 08 90 01 04 a3 90 01 04 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}