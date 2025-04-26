
rule TrojanSpy_Win32_Paglec_A{
	meta:
		description = "TrojanSpy:Win32/Paglec.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 31 2e 30 } //1 %s?mac=%s&ver=1.0
		$a_01_1 = {61 72 70 6c 67 6d 2e 63 6e 2f 43 6f 75 6e 74 2f 43 6f 75 6e 74 2e 61 73 70 } //1 arplgm.cn/Count/Count.asp
		$a_01_2 = {64 2e 74 78 74 7c 43 3a 5c 62 6f 6f 74 } //1 d.txt|C:\boot
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}