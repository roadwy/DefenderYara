
rule Trojan_Win32_QQpass_FZ{
	meta:
		description = "Trojan:Win32/QQpass.FZ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 54 24 10 8b 4c 24 08 30 14 08 40 3b c6 7c f8 } //1
		$a_01_1 = {73 65 6e 64 64 61 74 61 2e 61 73 70 3f 31 3d 61 62 63 64 65 66 67 26 32 3d 31 32 33 34 35 36 37 26 33 3d } //1 senddata.asp?1=abcdefg&2=1234567&3=
		$a_01_2 = {48 65 6e 77 61 79 00 } //1
		$a_01_3 = {54 58 47 75 69 46 6f 75 6e 64 61 74 69 6f 6e 00 } //1 塔畇䙩畯摮瑡潩n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}