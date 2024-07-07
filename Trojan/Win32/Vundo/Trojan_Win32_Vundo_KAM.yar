
rule Trojan_Win32_Vundo_KAM{
	meta:
		description = "Trojan:Win32/Vundo.KAM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 00 f0 ff ff 90 02 25 23 c1 90 02 40 2d 00 10 00 00 90 01 05 90 02 20 8b 08 90 02 14 81 e1 ff ff 00 00 81 f9 4d 5a 00 00 0f 85 90 01 01 ff ff ff 90 02 12 8d 48 3c 8b 09 90 01 10 90 02 20 81 e1 ff ff 00 00 90 01 05 90 02 25 81 f9 50 45 00 00 0f 84 90 01 02 00 00 90 02 20 33 c0 c3 90 00 } //1
		$a_03_1 = {89 55 fc 33 c0 c1 c0 90 01 06 90 02 25 32 02 42 80 3a 00 0f 85 90 01 01 ff ff ff 3b 45 0c 0f 84 90 01 01 00 00 00 90 02 20 46 90 02 20 3b 73 18 0f 82 90 01 01 ff ff ff 90 02 ff 83 ec 04 c7 04 24 90 01 04 81 04 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}