
rule Trojan_Win32_Vundo_gen_AV{
	meta:
		description = "Trojan:Win32/Vundo.gen!AV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 fa 2e 75 54 8a 51 01 80 ca 20 80 fa 64 75 49 8a 51 02 80 ca 20 80 fa 6c 75 3e 8a 51 03 80 ca 20 80 fa 6c 75 } //1
		$a_03_1 = {c1 e8 1f f7 d0 a8 01 74 90 01 01 81 e7 ff 00 00 00 83 ff 05 72 90 00 } //1
		$a_03_2 = {0f b7 04 02 03 c6 33 d2 8b 5d 0c f7 f3 8b f2 89 75 90 01 01 8a 04 0f 88 45 e7 8a 14 0e 88 14 0f 88 04 0e 47 89 7d 90 01 01 8b 55 90 01 01 eb 90 00 } //1
		$a_01_3 = {7d 15 33 c9 8a 4c 05 c4 33 d2 8a 54 05 d4 33 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}