
rule Trojan_Win32_Moxtrarch_A{
	meta:
		description = "Trojan:Win32/Moxtrarch.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 65 67 6f 70 61 79 2e 72 75 2f 6e 75 6d 2f } //1 http://egopay.ru/num/
		$a_01_1 = {33 2e 20 c4 eb ff 20 e7 e0 e2 e5 f0 f8 e5 ed e8 ff 20 e7 e0 e3 f0 f3 e7 ea e8 20 ed e5 ee e1 f5 } //2
		$a_01_2 = {c8 d7 cd c0 df 20 ce d4 c5 d0 d2 c0 20 ce c1 20 c8 d1 cf ce cb dc c7 ce c2 c0 cd c8 c8 20 d1 c5 } //2
		$a_01_3 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 65 72 2e 6d 6f 6e 65 79 65 78 74 72 65 2e 6d 65 2f 61 64 64 73 75 62 73 63 72 69 70 74 69 6f 6e 2e 70 68 70 3f 61 62 6f 6e 3d 37 } //3 http://counter.moneyextre.me/addsubscription.php?abon=7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=8
 
}