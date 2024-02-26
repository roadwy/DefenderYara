
rule Trojan_Win32_DarkGate_ZZ{
	meta:
		description = "Trojan:Win32/DarkGate.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,fffffff1 00 fffffff1 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {80 e1 3f c1 e1 02 8a 5d 90 01 01 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb 90 00 } //64 00 
		$a_03_2 = {80 e1 0f c1 e1 04 8a 5d 90 01 01 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb 90 00 } //0a 00 
		$a_81_3 = {5f 5f 5f 5f 70 61 64 6f 72 75 5f 5f 5f 5f } //0a 00  ____padoru____
		$a_81_4 = {45 72 72 6f 72 3a 20 6e 6f 20 64 65 6c 69 6d 69 74 61 64 6f 72 20 6d 6f 6e 69 74 6f 72 } //0a 00  Error: no delimitador monitor
		$a_81_5 = {68 76 6e 63 20 65 72 72 6f 72 } //0a 00  hvnc error
		$a_81_6 = {2d 61 63 63 65 70 74 65 75 6c 61 20 2d 64 20 2d 75 20 } //00 00  -accepteula -d -u 
		$a_00_7 = {5d 04 00 00 f1 3b 06 80 5c 27 00 00 f2 3b 06 80 00 00 01 00 08 00 11 00 ac 21 44 61 72 6b 47 61 74 65 2e 5a 5a 21 73 6d 73 00 00 01 40 05 82 70 00 04 00 ce 09 00 00 9a 9e 54 e7 78 b2 00 00 7b 5d 04 00 00 f2 3b 06 80 5c 37 00 00 f3 3b 06 80 00 00 01 00 08 00 21 00 54 72 6f 6a 61 6e 3a 50 6f 77 65 72 53 68 65 6c 6c 2f 50 73 68 65 6c 6c 52 75 6e 64 6c 6c 2e 53 41 00 00 01 40 05 82 70 00 04 00 e7 66 00 00 00 00 62 00 ad e6 17 d1 67 ac 1a 80 0b c7 18 80 ea ea e3 ad c7 17 c7 31 bc 3f 8f c0 e7 89 e3 ec 04 f2 ea 80 c7 f2 52 80 e7 fc 74 33 33 33 fe e3 36 e7 89 e3 ec 04 f2 ea 80 c7 f2 52 80 e7 fc 9a 33 33 33 fe 14 e0 8f c7 05 67 0f ec 67 ac 1a 80 0b c7 18 80 ea ea 78 67 d1 18 80 ea ea 93 da 3f 13 ea ea fe c7 e3 5d 04 00 } //00 f3 
	condition:
		any of ($a_*)
 
}