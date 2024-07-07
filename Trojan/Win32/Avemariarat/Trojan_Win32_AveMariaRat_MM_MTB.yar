
rule Trojan_Win32_AveMariaRat_MM_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 88 83 c1 01 89 4d 88 8b 55 84 83 ea 01 39 55 88 7f 33 8b 45 84 83 e8 01 2b 45 88 8b 8d 64 ff ff ff 8b 14 81 f7 d2 89 95 70 ff ff ff 83 bd 70 ff ff ff 00 74 0e 8b 45 80 03 45 88 8a 8d 70 ff ff ff 88 08 eb b9 } //1
		$a_01_1 = {b8 01 00 00 00 6b c8 00 ba 01 00 00 00 6b c2 00 8b 55 94 8a 0c 0a 88 4c 05 90 ba 01 00 00 00 c1 e2 00 b8 01 00 00 00 c1 e0 00 8b 4d 94 8a 14 11 88 54 05 90 b8 01 00 00 00 d1 e0 b9 01 00 00 00 d1 e1 8b 55 94 8a 04 02 88 44 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}