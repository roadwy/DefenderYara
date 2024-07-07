
rule Trojan_Win32_Smominru_A{
	meta:
		description = "Trojan:Win32/Smominru.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 34 2e 6d 79 78 6d 72 2e 70 77 3a 38 38 38 38 2f 36 34 2e 72 61 72 } //1 64.myxmr.pw:8888/64.rar
		$a_01_1 = {36 34 2e 6d 79 78 6d 72 2e 70 77 3a 38 38 38 38 2f 63 63 2e 72 61 72 } //1 64.myxmr.pw:8888/cc.rar
		$a_01_2 = {78 6d 72 2e 35 62 36 62 37 62 2e 72 75 3a 38 38 38 38 2f 78 6d 72 6f 6b 2e 74 78 74 } //1 xmr.5b6b7b.ru:8888/xmrok.txt
		$a_01_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 64 65 62 75 67 5c 6c 73 6d 6f 73 65 2e 65 78 65 } //1 c:\windows\debug\lsmose.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}