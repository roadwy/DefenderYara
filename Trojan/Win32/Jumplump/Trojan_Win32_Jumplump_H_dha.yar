
rule Trojan_Win32_Jumplump_H_dha{
	meta:
		description = "Trojan:Win32/Jumplump.H!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 0a 00 00 "
		
	strings :
		$a_01_0 = {41 bf 10 e1 8a c3 e9 } //2
		$a_01_1 = {41 bf 5d 44 11 ff e9 } //2
		$a_01_2 = {41 bf 4c 77 d6 07 e9 } //2
		$a_01_3 = {41 bf 40 de ce 72 e9 } //2
		$a_01_4 = {41 bf 49 f7 02 78 e9 } //2
		$a_01_5 = {41 bf 6c b0 85 db e9 } //2
		$a_01_6 = {ba 60 00 00 00 e9 } //1
		$a_01_7 = {65 48 8b 12 e9 } //1
		$a_01_8 = {48 81 ee 02 10 00 00 e9 } //1
		$a_01_9 = {66 3d 4d 5a e9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}